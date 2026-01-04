#!/usr/bin/env perl
use v5.20;
use strict;
use warnings;
use utf8;
use open qw(:std :utf8);

use Mojolicious::Lite;
use Mojo::Log;
use Mojo::File qw(path);
use Mojo::Promise;
use Mojo::Util;
use Mojo::JSON qw(decode_json encode_json);
use Mojo::Date;
use FindBin qw($Bin);
use File::Copy qw(copy);
use Net::CIDR;
use Fcntl qw(:flock);

our $VERSION = '1.1.0'; 

# Rate-Limits muessen request-uebergreifend sein, deshalb bewusst global
my %rate_limits;

# Config Cache, bewusst global im Prozess, aber lexikal statt our
my $CONFIG_CACHE;

# =============================================
# HELPER
# =============================================

sub ensure_dir {
    my ($p) = @_;
    return 1 unless $p;
    my $dir = -d $p ? path($p) : path($p)->dirname;
    return 1 if -d $dir->to_string && -w $dir->to_string;
    eval { $dir->make_path; 1 } or do {
        app->log->warn("Konnte Verzeichnis nicht anlegen: $p");
        return 0;
    };
    return 1;
}

sub chown_safe {
    my ($p, $uid, $gid) = @_;
    return 1 unless defined $p && -e $p;
    eval { chown $uid, $gid, $p or die $!; 1 } or do {
        app->log->warn("chown fehlgeschlagen fuer $p: $!");
        return 0;
    };
    return 1;
}

sub chmod_safe {
    my ($p, $mode) = @_;
    return 1 unless defined $p && -e $p;
    eval { chmod $mode, $p or die $!; 1 } or do {
        app->log->warn("chmod fehlgeschlagen fuer $p: $!");
        return 0;
    };
    return 1;
}

sub _ts_yyyymmdd_hhmmss {
    my @t = localtime(time);
    return sprintf(
        '%04d%02d%02d_%02d%02d%02d',
        $t[5] + 1900, $t[4] + 1, $t[3],
        $t[2], $t[1], $t[0]
    );
}

sub client_ip {
    my ($c, $ctx) = @_;
    my $rip = $c->tx->remote_address // '';
    my $trusted = $ctx->{net}{trusted_proxies} // [];
    return $rip unless @$trusted;

    my $is_trusted = grep { $_ eq $rip } @$trusted;
    return $rip unless $is_trusted;

    my $headers = $ctx->{net}{ip_headers} // [];
    for my $header (@$headers) {
        my $h = $c->req->headers->header($header) // '';
        next unless $h;
        my ($first) = split /\s*,\s*/, $h;
        $first =~ s/^\s+|\s+$//g;
        return $first if $first =~ /^[0-9a-fA-F:\.]+$/;
    }
    return $rip;
}

sub fail_json {
    my ($c, $ctx, $msg, $st) = @_;
    $st //= 400;
    app->log->error("$msg (IP: " . client_ip($c, $ctx) . ", Path: " . $c->req->url->path . ")");
    $c->render(json => { ok => 0, error => $msg, status => $st }, status => $st);
}

sub success_json {
    my ($c, $d, $st) = @_;
    $st //= 200;
    $d->{ok} = 1 unless exists $d->{ok};
    $d->{status} = $st unless exists $d->{status};
    app->log->info("Erfolgreich: status=$st");
    $c->render(json => $d, status => $st);
}

# =============================================
# FILE LOCKING & ATOMIC UPLOAD
# =============================================

sub atomic_upload {
    my ($ctx, $up, $dest) = @_;
    return 0 unless $up && $dest;
    return 0 unless $up->headers->content_type && $up->headers->content_type eq 'application/json';

    # JSON-Validierung vor dem Speichern
    my $json_content = $up->slurp;
    eval { decode_json($json_content); 1 } or do {
        app->log->error("Ungueltiges JSON im Upload: $@");
        return 0;
    };

    my $tmpDir = $ctx->{paths}{tmpDir};
    my $tmpFileMode = $ctx->{modes}{tmpFileMode};
    my $fileModeDeploy = $ctx->{modes}{fileModeDeploy};
    my $deployUID = $ctx->{ids}{deployUID};
    my $deployGID = $ctx->{ids}{deployGID};

    my $tmp = path($tmpDir, sprintf("upload_%d_%d_%d", $$, time, int(rand(1e6))))->to_string;

    eval {
        ensure_dir($tmpDir) or die "tmpDir nicht vorhanden oder nicht beschreibbar";
        $up->move_to($tmp) or die "move_to fehlgeschlagen: " . $up->error;
        chmod_safe($tmp, $tmpFileMode);

        open my $dest_fh, '>>', $dest or die "Kann $dest nicht oeffnen: $!";
        flock($dest_fh, LOCK_EX) or die "Kann $dest nicht sperren: $!";

        ensure_dir(path($dest)->dirname->to_string) or die "Zielverzeichnis fehlt oder ist nicht beschreibbar";

        unless (rename $tmp, $dest) {
            copy($tmp, $dest) or die "copy fehlgeschlagen: $!";
            unlink $tmp or app->log->warn("Kann temporaere Datei nicht loeschen: $tmp");
        }

        flock($dest_fh, LOCK_UN);
        close $dest_fh;

        chmod_safe($dest, $fileModeDeploy);
        chown_safe($dest, $deployUID, $deployGID);

        app->log->info("Upload gespeichert: $dest (Size: " . (-s $dest) . " bytes)");
        1;
    } or do {
        app->log->error("Upload fehlgeschlagen ($dest): $@");
        unlink $tmp if -e $tmp;
        return 0;
    };

    return 1;
}

# =============================================
# BACKUP & HOUSEKEEPING
# =============================================

sub create_file_backup {
    my ($ctx, $kind, $source_file) = @_;
    return unless -f $source_file;

    my $backupDir = $ctx->{paths}{backupDir};
    my $maxBackupAgeDays = $ctx->{limits}{maxBackupAgeDays};
    my $maxBackups = $ctx->{limits}{maxBackups};
    my $fileModeService = $ctx->{modes}{fileModeService};

    Mojo::IOLoop->subprocess(
        sub {
            my $ts = _ts_yyyymmdd_hhmmss();
            my $dest = path($backupDir, "${kind}_${ts}.json")->to_string;
            eval {
                ensure_dir($backupDir) or die "backupDir fehlt";

                open my $src_fh, '<', $source_file or die "Kann $source_file nicht oeffnen: $!";
                flock($src_fh, LOCK_SH) or die "Kann $source_file nicht sperren: $!";
                copy($source_file, $dest) or die "copy fehlgeschlagen: $!";
                flock($src_fh, LOCK_UN);
                close $src_fh;

                chmod_safe($dest, $fileModeService);

                my $dir = path($backupDir);
                my @names = (-d $dir->to_string) ? map { $_->basename } $dir->list->each : ();
                my @list = sort { $b cmp $a }
                    grep { /^\Q${kind}_\E\d{8}_\d{6}\.json$/ }
                    map { path($backupDir, $_)->to_string } @names;

                my $now = time;
                for my $f (@list) {
                    my $mtime = (stat($f))[9];
                    my $age_days = int(($now - $mtime) / 86400);

                    if ($age_days > $maxBackupAgeDays || @list > $maxBackups) {
                        unlink $f or app->log->warn("Kann Backup nicht loeschen $f: $!");
                    }
                }
                1;
            } or app->log->error("Backup fehlgeschlagen: $@");
        },
        sub {
            my ($subprocess, $err) = @_;
            if ($err) {
                app->log->error("Async Backup fehlgeschlagen: $err");
            } else {
                app->log->info("Async Backup erfolgreich: $source_file");
            }
        }
    );
}

# =============================================
# KONFIGURATION LADEN (mit flock)
# =============================================

sub load_config_uncached {
    my $configfile = path($Bin, 'config.json')->to_string;
    die "Config $configfile fehlt!\n" unless -f $configfile;
    die "Config $configfile ist nicht lesbar!\n" unless -r $configfile;

    open my $fh, '<:raw', $configfile or die "Kann Config $configfile nicht oeffnen: $!\n";
    flock($fh, LOCK_SH) or die "Kann Config $configfile nicht sperren: $!\n";

    local $/ = undef;
    my $json = <$fh>;
    close $fh;

    die "Config $configfile ist leer!\n" unless defined $json && length($json);
    $json =~ s/^\xEF\xBB\xBF//; # UTF-8 BOM entfernen
    $json =~ s/^\s+//;
    $json =~ s/\s+$//;
    die "Config $configfile ist nach Trim leer!\n" unless length($json);

    my $config;
    eval { $config = decode_json($json); 1 } or die "Config JSON ungueltig ($configfile): $@\n";
    die "Config JSON ist kein Objekt\n" unless ref($config) eq 'HASH';

    $config->{maxUploadMB}        //= 25;
    $config->{fileMode_service}   //= '0660';
    $config->{fileMode_deploy}    //= '0660';
    $config->{tmpFileMode}        //= '0660';
    $config->{maxBackups}         //= 20;
    $config->{maxBackupAgeDays}   //= 30;
    $config->{allowed_ips}        //= ['127.0.0.1'];
    $config->{client_ip_header}   //= 'X-Forwarded-For';

    my @acl_cidrs = ref $config->{allowed_ips} eq 'ARRAY'
        ? @{$config->{allowed_ips}}
        : split /\s*,\s*/, ($config->{allowed_ips} // '127.0.0.1');

    for my $cidr (@acl_cidrs) {
        die "Ungueltige CIDR-Notation: $cidr\n" unless Net::CIDR::cidrvalidate($cidr);
    }

    return $config;
}

sub get_config {
    $CONFIG_CACHE //= load_config_uncached();
    return $CONFIG_CACHE;
}

sub invalidate_config_cache {
    $CONFIG_CACHE = undef;
}

# =============================================
# INITIALISIERUNG
# =============================================

my $Config = get_config();

my $max_mb    = $Config->{maxUploadMB} // 25;
my $max_bytes = $max_mb * 1024 * 1024;
$ENV{MOJO_MAX_MESSAGE_SIZE} = $max_bytes;
app->max_request_size($max_bytes);

my $api_token = $ENV{API_TOKEN} or die "ENV API_TOKEN ist erforderlich!\n";
my $LOGFILE   = $Config->{logfile} // '/var/log/hec/autoreply-agent.log';

my @acl_cidrs = ref $Config->{allowed_ips} eq 'ARRAY'
    ? @{ $Config->{allowed_ips} }
    : split /\s*,\s*/, ($Config->{allowed_ips} // '127.0.0.1');

my @trusted_proxies = ref($Config->{trusted_proxies}) eq 'ARRAY'
    ? @{ $Config->{trusted_proxies} }
    : split /\s*,\s*/, ($Config->{trusted_proxies} // '');

my @ip_headers = (
    $Config->{client_ip_header} // 'X-Forwarded-For',
    'X-Real-IP',
    'CF-Connecting-IP',
);

my $configDir   = $Config->{configDir}   or die "configDir fehlt!";
my $jsonDir     = $Config->{jsonDir}     or die "jsonDir fehlt!";
my $templateDir = $Config->{templateDir} // '';
my $statslog    = $Config->{statslog}    or die "statslog fehlt!";
my $backupDir   = $Config->{backupDir}   or die "backupDir fehlt!";
my $tmpDir      = $Config->{tmpDir}      or die "tmpDir fehlt!";

my $maxBackups        = $Config->{maxBackups}       // 20;
my $maxBackupAgeDays  = $Config->{maxBackupAgeDays} // 30;

my $fileModeService = oct($Config->{fileMode_service} // '0660');
my $fileModeDeploy  = oct($Config->{fileMode_deploy}  // '0660');
my $tmpFileMode     = oct($Config->{tmpFileMode}      // '0660');

my $deployUser  = $Config->{deployUser}  or die "deployUser fehlt!";
my $deployGroup = $Config->{deployGroup} or die "deployGroup fehlt!";
my $deployUID   = getpwnam($deployUser)  // die "Benutzer $deployUser existiert nicht!";
my $deployGID   = getgrnam($deployGroup) // die "Gruppe $deployGroup existiert nicht!";

my $CTX = {
    config => $Config,
    net => {
        acl_cidrs        => \@acl_cidrs,
        trusted_proxies  => \@trusted_proxies,
        ip_headers       => \@ip_headers,
        api_token        => $api_token,
    },
    paths => {
        configDir => $configDir,
        jsonDir   => $jsonDir,
        templateDir => $templateDir,
        statslog  => $statslog,
        backupDir => $backupDir,
        tmpDir    => $tmpDir,
        logfile   => $LOGFILE,
    },
    modes => {
        fileModeService => $fileModeService,
        fileModeDeploy  => $fileModeDeploy,
        tmpFileMode     => $tmpFileMode,
    },
    ids => {
        deployUID => $deployUID,
        deployGID => $deployGID,
    },
    limits => {
        maxBackups       => $maxBackups,
        maxBackupAgeDays => $maxBackupAgeDays,
    },
};

ensure_dir(path($LOGFILE)->dirname->to_string) or die "Konnte Logdir nicht anlegen: " . path($LOGFILE)->dirname . "\n";
open(my $lfh, '>>:encoding(UTF-8)', $LOGFILE) or die "Logfile nicht schreibbar: $LOGFILE ($!)\n";
close $lfh;

chmod_safe($LOGFILE, $fileModeService);
chown_safe($LOGFILE, $deployUID, $deployGID);

app->log->path($LOGFILE);
app->log->level('info');

for my $p ($configDir, $jsonDir, $templateDir, path($statslog)->dirname->to_string, $backupDir, $tmpDir) {
    next unless $p;
    unless (ensure_dir($p)) {
        app->log->error("Konnte Verzeichnis nicht anlegen: $p");
        die "Kritischer Fehler: Verzeichnis $p fehlt oder ist nicht anlegbar\n";
    }
}

for my $p (grep { $_ } ($configDir, $jsonDir, $templateDir, $statslog)) {
    my $target = $p;
    if (-e $target) {
        chown_safe($target, $deployUID, $deployGID);
    } else {
        my $parent = path($target)->dirname->to_string;
        ensure_dir($parent);
        chown_safe($parent, $deployUID, $deployGID);
    }
}

# =============================================
# HOOKS
# =============================================

app->hook(around_dispatch => sub {
    my ($next, $c) = @_;
    my $ok = eval { $next->(); 1 };
    return if $ok;
    my $err = $@ || 'Unknown error';
    app->log->error("Request failed: $err (IP: " . client_ip($c, $CTX) . ", Path: " . $c->req->url->path . ")");
    $c->res->code(500);
    $c->res->headers->content_type('application/json; charset=UTF-8');
    $c->render(json => { ok => 0, error => "$err" });
});

hook before_dispatch => sub {
    my $c = shift;
    my $ip = client_ip($c, $CTX);
    my $now = time;
    if (!$rate_limits{$ip} || $rate_limits{$ip}{last} < $now - 1) {
        $rate_limits{$ip} = { count => 1, last => $now };
    } else {
        $rate_limits{$ip}{count}++;
        if ($rate_limits{$ip}{count} > 10) {
            return $c->render(json => { ok => 0, error => "Rate limit exceeded. Try again later." }, status => 429);
        }
    }
};

hook before_dispatch => sub {
    my $c = shift;
    my $ip = client_ip($c, $CTX);

    return fail_json($c, $CTX, "Forbidden IP $ip", 403)
        unless Net::CIDR::cidrlookup($ip, @{ $CTX->{net}{acl_cidrs} });

    my $hdr = $c->req->headers->header('X-API-Token');
    return fail_json($c, $CTX, "Unauthorized: missing X-API-Token", 401) unless defined $hdr;
    return fail_json($c, $CTX, "Unauthorized: invalid API token", 401) unless $hdr eq $CTX->{net}{api_token};
};

hook after_dispatch => sub {
    my $c = shift;
    if ($c->req->url->path =~ m{/autoreply/(server|user)/config$} && $c->req->method eq 'POST') {
        invalidate_config_cache();
    }
};

Mojo::IOLoop->recurring(86400 => sub {
    my $now = time;
    my $cutoff = $now - (3600 * 24);
    my $dir = path($CTX->{paths}{tmpDir});

    if (-d $dir->to_string) {
        $dir->list->each(sub {
            my ($f) = @_;
            return unless -f $f->to_string;
            my $mtime = (stat($f->to_string))[9];
            if ($mtime < $cutoff) {
                unlink $f->to_string or app->log->warn("Kann " . $f->to_string . " nicht loeschen: $!");
            }
        });
    } else {
        app->log->error("Kann tmpDir nicht oeffnen: " . $CTX->{paths}{tmpDir});
    }

    %rate_limits = ();
    app->log->info("Housekeeping: Alte temporaere Dateien geloescht und Rate-Limits zurueckgesetzt.");
});

# =============================================
# ROUTEN
# =============================================

# --- Root (Discovery-Endpunkt) ---
get '/' => sub {
    my $c = shift;
    my @routes_list;

    foreach my $route (@{app->routes->children}) {
        next unless ref $route;
        my $methods = $route->via;
        my $method_str = (ref $methods eq 'ARRAY' && @$methods)
            ? join(', ', map { uc } @$methods)
            : 'ANY';
        my $p = $route->to_string;
        push @routes_list, { method => $method_str, path => $p };
    }

    @routes_list = sort { $a->{path} cmp $b->{path} } @routes_list;

    $c->render(json => {
        ok            => 1,
        name          => 'autoreply-config-manager',
        version       => $VERSION,
        api_endpoints => \@routes_list
    });
};



post '/autoreply/server/config' => sub {
    my $c = shift;
    my $up = $c->req->upload('config') or return fail_json($c, $CTX, "No config uploaded", 400);
    my $f = path($CTX->{paths}{configDir}, 'autoreply_server.json')->to_string;

    create_file_backup($CTX, 'server', $f) if -f $f;
    atomic_upload($CTX, $up, $f) or return fail_json($c, $CTX, "Upload fehlgeschlagen", 500);
    success_json($c, {});
};

get '/autoreply/server/config' => sub {
    my $c = shift;
    my $f = path($CTX->{paths}{configDir}, 'autoreply_server.json')->to_string;
    return fail_json($c, $CTX, "Config not found", 404) unless -f $f;
    $c->res->headers->content_disposition('attachment; filename="autoreply_server.json"');
    $c->reply->file($f);
};

post '/autoreply/user/config' => sub {
    my $c = shift;
    my $up = $c->req->upload('config') or return fail_json($c, $CTX, "No config uploaded", 400);
    my $f = path($CTX->{paths}{jsonDir}, 'autoreply_user.json')->to_string;

    create_file_backup($CTX, 'user', $f) if -f $f;
    atomic_upload($CTX, $up, $f) or return fail_json($c, $CTX, "Upload fehlgeschlagen", 500);
    success_json($c, {});
};

get '/autoreply/user/config' => sub {
    my $c = shift;
    my $f = path($CTX->{paths}{jsonDir}, 'autoreply_user.json')->to_string;
    return fail_json($c, $CTX, "Config not found", 404) unless -f $f;
    $c->res->headers->content_disposition('attachment; filename="autoreply_user.json"');
    $c->reply->file($f);
};

get '/autoreply/backups' => sub {
    my $c = shift;
    my (@user, @server);
    my $dir = path($CTX->{paths}{backupDir});
    if (-d $dir->to_string) {
        my @names = map { $_->basename } $dir->list->each;
        @user = sort { $b cmp $a } grep { /^user_\d{8}_\d{6}\.json$/ } @names;
        @server = sort { $b cmp $a } grep { /^server_\d{8}_\d{6}\.json$/ } @names;
    }
    success_json($c, { backups => [@user, @server] });
};

get '/autoreply/backup/*filename' => sub {
    my $c = shift;
    my $fn = $c->stash('filename') // '';
    $fn =~ s{[^a-zA-Z0-9_.-]}{}g;
    return fail_json($c, $CTX, "Invalid filename", 400) unless $fn =~ /^(user|server)_\d{8}_\d{6}\.json$/;

    my $f = path($CTX->{paths}{backupDir}, $fn)->to_string;
    return fail_json($c, $CTX, "File not found", 404) unless -f $f;

    my $abs_b = path($CTX->{paths}{backupDir})->to_abs->to_string;
    my $abs_f = path($f)->to_abs->to_string;
    return fail_json($c, $CTX, "Invalid path", 400) unless index($abs_f, $abs_b) == 0;

    $c->res->headers->content_disposition("attachment; filename=\"$fn\"");
    $c->reply->file($f);
};

get '/autoreply/statslog' => sub {
    my $c = shift;
    return fail_json($c, $CTX, "Stats-Log not found", 404) unless -f $CTX->{paths}{statslog};
    chown_safe($CTX->{paths}{statslog}, $CTX->{ids}{deployUID}, $CTX->{ids}{deployGID});
    $c->res->headers->content_disposition('attachment; filename="autoreply_stats.log"');
    $c->reply->file($CTX->{paths}{statslog});
};

get '/health' => sub {
    my $c = shift;
    my %status;
    for my $p ($CTX->{paths}{configDir}, $CTX->{paths}{jsonDir}, $CTX->{paths}{backupDir}, $CTX->{paths}{tmpDir}, path($CTX->{paths}{logfile})->dirname->to_string) {
        $status{$p} = { exists => -e $p, writable => -w $p };
    }
    my @errors;
    for my $p (keys %status) {
        push @errors, "$p: " . join(', ', grep { !$status{$p}{$_} } keys %{$status{$p}}) unless $status{$p}{exists} && $status{$p}{writable};
    }
    return fail_json($c, $CTX, "Check failed: " . join('; ', @errors), 503) if @errors;
    success_json($c, { status => 'ok', details => \%status });
};

any '/*whatever' => sub {
    my $c = shift;
    fail_json($c, $CTX, "Unbekannte Route: " . $c->req->method . " " . $c->req->url->path, 404);
};

# =============================================
# SSL & START
# =============================================

if ($Config->{ssl_enable}) {
    my $ssl_cert = $Config->{ssl_cert_file} // die "ssl_cert_file fehlt in Config!";
    my $ssl_key  = $Config->{ssl_key_file}  // die "ssl_key_file fehlt in Config!";

    die "SSL-Zertifikat nicht lesbar: $ssl_cert\n" unless -r $ssl_cert;
    die "SSL-Key nicht lesbar: $ssl_key\n" unless -r $ssl_key;
    die "SSL-Zertifikat ist leer: $ssl_cert\n" unless -s $ssl_cert;
    die "SSL-Key ist leer: $ssl_key\n" unless -s $ssl_key;
}

my $listen_addr = $Config->{listen} // '0.0.0.0:5000';
my $listen_url  = $Config->{ssl_enable}
    ? "https://$listen_addr?cert=$Config->{ssl_cert_file}&key=$Config->{ssl_key_file}"
    : "http://$listen_addr";

app->log->info("App gestartet auf $listen_url");
app->start('daemon', '-l', $listen_url);

