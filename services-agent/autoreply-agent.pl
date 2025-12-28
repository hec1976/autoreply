#!/usr/bin/env perl
use v5.20;
use strict;
use warnings;

# --- Core Modules ---
use Mojolicious::Lite;
use JSON::MaybeXS qw(decode_json);
use File::Basename qw(basename dirname);
use File::Copy qw(copy);
use File::Spec;
use File::Glob ':glob';
use Net::CIDR;
use FindBin qw($Bin);
use IO::Handle ();
use Time::Piece;
use File::Path qw(make_path);
use Fcntl qw(SEEK_SET :flock);

# --- Globale Variablen ---
umask 0007;
my $Config;
my %rate_limits;  # Für manuelles Rate Limiting

# =============================================
# HELPER-FUNKTIONEN
# =============================================

sub ensure_dir {
    my ($path) = @_;
    return 1 unless $path;
    my $dir = -d $path ? $path : dirname($path);
    return 1 if -d $dir && -w $dir;
    eval { make_path($dir); 1 } or do {
        app->log->warn("Konnte Verzeichnis nicht anlegen: $path");
        return 0;
    };
    return 1;
}

sub chown_safe {
    my ($path, $uid, $gid) = @_;
    return 1 unless -e $path;
    eval { chown $uid, $gid, $path or die $!; 1 } or do {
        app->log->warn("chown fehlgeschlagen für $path: $!");
        return 0;
    };
    return 1;
}

sub chmod_safe {
    my ($path, $mode) = @_;
    return 1 unless -e $path;
    eval { chmod $mode, $path or die $!; 1 } or do {
        app->log->warn("chmod fehlgeschlagen für $path: $!");
        return 0;
    };
    return 1;
}

sub client_ip {
    my ($c) = @_;
    my $rip = $c->tx->remote_address // '';
    return $rip unless @trusted_proxies;
    my $is_trusted = grep { $_ eq $rip } @trusted_proxies;
    return $rip unless $is_trusted;
    for my $header (@ip_headers) {
        my $h = $c->req->headers->header($header) // '';
        next unless $h;
        my ($first) = split /\s*,\s*/, $h;
        $first =~ s/^\s+|\s+$//g;
        return $first if $first =~ /^[0-9a-fA-F:\.]+$/;
    }
    return $rip;
}

sub fail_json {
    my ($c, $msg, $st) = @_;
    $st //= 400;
    app->log->error("$msg (IP: " . client_ip($c) . ", Path: " . $c->req->url->path . ")");
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
    my ($up, $dest) = @_;
    return 0 unless $up && $dest;
    return 0 unless $up->headers->content_type && $up->headers->content_type eq 'application/json';

    my $tmp = sprintf "%s/upload_%d_%d_%d", $tmpDir, $$, time, int(rand(1e6));
    eval {
        ensure_dir($tmpDir) or die "tmpDir nicht vorhanden oder nicht beschreibbar";
        $up->move_to($tmp) or die "move_to fehlgeschlagen: " . $up->error;
        chmod_safe($tmp, $tmpFileMode);

        # Exklusive Dateisperre für Ziel
        open my $dest_fh, '>>', $dest or die "Kann $dest nicht öffnen: $!";
        flock($dest_fh, LOCK_EX) or die "Kann $dest nicht sperren: $!";
        ensure_dir(dirname($dest)) or die "Zielverzeichnis fehlt oder ist nicht beschreibbar";
        if (!rename $tmp, $dest) {
            copy($tmp, $dest) or die "copy fehlgeschlagen: $!";
            unlink $tmp or app->log->warn("Kann temporäre Datei nicht löschen: $tmp");
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
    my ($kind, $source_file) = @_;
    return unless -f $source_file;

    Mojo::IOLoop->subprocess(
        sub {
            my $ts = localtime->strftime('%Y%m%d_%H%M%S');
            my $dest = File::Spec->catfile($backupDir, "${kind}_${ts}.json");
            eval {
                ensure_dir($backupDir) or die "backupDir fehlt";
                open my $src_fh, '<', $source_file or die "Kann $source_file nicht öffnen: $!";
                flock($src_fh, LOCK_SH) or die "Kann $source_file nicht sperren: $!";
                copy($source_file, $dest) or die "copy fehlgeschlagen: $!";
                flock($src_fh, LOCK_UN);
                close $src_fh;
                chmod_safe($dest, $fileModeService);

                # Alte Backups bereinigen
                my @list = sort { $b cmp $a } bsd_glob("$backupDir/${kind}_*.json");
                my $now = time;
                for my $old (@list) {
                    my $mtime = (stat($old))[9];
                    my $age_days = int(($now - $mtime) / 86400);
                    if ($age_days > $maxBackupAgeDays || @list > $maxBackups) {
                        unlink $old or app->log->warn("Kann Backup nicht löschen $old: $!");
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
# KONFIGURATION LADEN
# =============================================

sub load_config {
    return $Config if $Config;
    my $configfile = "$Bin/config.json";
    die "Config $configfile fehlt!\n" unless -f $configfile;

    open my $fh, "<:encoding(UTF-8)", $configfile or die "Config nicht lesbar: $!";
    local $/;
    my $json = <$fh>;
    close $fh;

    my $config;
    eval { $config = decode_json($json); 1 } or die "Config JSON ungültig ($configfile): $@\n";
    die "Config JSON ist kein Objekt\n" unless ref($config) eq 'HASH';

    # Defaults
    $config->{maxUploadMB}        //= 25;
    $config->{fileMode_service}   //= '0660';
    $config->{fileMode_deploy}    //= '0660';
    $config->{tmpFileMode}        //= '0660';
    $config->{maxBackups}         //= 20;
    $config->{maxBackupAgeDays}   //= 30;
    $config->{allowed_ips}        //= ['127.0.0.1'];
    $config->{client_ip_header}   //= 'X-Forwarded-For';

    # CIDR-Validierung
    my @acl_cidrs = ref $config->{allowed_ips} eq 'ARRAY'
        ? @{$config->{allowed_ips}}
        : split /\s*,\s*/, ($config->{allowed_ips} // '127.0.0.1');
    for my $cidr (@acl_cidrs) {
        die "Ungültige CIDR-Notation: $cidr\n" unless Net::CIDR::cidrvalidate($cidr);
    }

    $Config = $config;
    return $Config;
}

# =============================================
# INITIALISIERUNG
# =============================================

$Config = load_config();
my $max_mb = $Config->{maxUploadMB} // 25;
my $max_bytes = $max_mb * 1024 * 1024;
$ENV{MOJO_MAX_MESSAGE_SIZE} = $max_bytes;
app->max_request_size($max_bytes);

# API-Token
my $api_token = $ENV{API_TOKEN} or die "ENV API_TOKEN ist erforderlich!\n";

# Pfade und Berechtigungen
my $LOGFILE     = $Config->{logfile} // '/var/log/mmbb/autoreply-agent.log';
my @acl_cidrs   = ref $Config->{allowed_ips} eq 'ARRAY'
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

my $maxBackups      = $Config->{maxBackups}        // 20;
my $maxBackupAgeDays = $Config->{maxBackupAgeDays}  // 30;
my $fileModeService = oct($Config->{fileMode_service} // '0660');
my $fileModeDeploy  = oct($Config->{fileMode_deploy}  // '0660');
my $tmpFileMode     = oct($Config->{tmpFileMode}      // '0660');

my $deployUser  = $Config->{deployUser}  or die "deployUser fehlt!";
my $deployGroup = $Config->{deployGroup} or die "deployGroup fehlt!";
my $deployUID   = getpwnam($deployUser)  // die "Benutzer $deployUser existiert nicht!";
my $deployGID   = getgrnam($deployGroup) // die "Gruppe $deployGroup existiert nicht!";

# Log-Datei vorbereiten
ensure_dir(dirname($LOGFILE)) or die "Konnte Logdir nicht anlegen: " . dirname($LOGFILE) . "\n";
open(my $lfh, ">>:encoding(UTF-8)", $LOGFILE) or die "Logfile nicht schreibbar: $LOGFILE ($!)\n";
close $lfh;
chmod_safe($LOGFILE, $fileModeService);
chown_safe($LOGFILE, $deployUID, $deployGID);
app->log->path($LOGFILE);
app->log->level('info');

# Verzeichnisse sicherstellen
for my $p ($configDir, $jsonDir, $templateDir, dirname($statslog), $backupDir, $tmpDir) {
    next unless $p;
    unless (ensure_dir($p)) {
        app->log->error("Konnte Verzeichnis nicht anlegen: $p");
        die "Kritischer Fehler: Verzeichnis $p fehlt oder ist nicht anlegbar\n";
    }
}

# Ownership setzen
for my $p (grep { $_ } ($configDir, $jsonDir, $templateDir, $statslog)) {
    my $target = $p;
    if (-e $target) {
        chown_safe($target, $deployUID, $deployGID);
    } else {
        my $parent = dirname($target);
        ensure_dir($parent);
        chown_safe($parent, $deployUID, $deployGID);
    }
}

# =============================================
# HOOKS
# =============================================

# Fehlerbehandlung
app->hook(around_dispatch => sub {
    my ($next, $c) = @_;
    my $ok = eval { $next->(); 1 };
    return if $ok;
    my $err = $@ || 'Unknown error';
    app->log->error("Request failed: $err (IP: " . client_ip($c) . ", Path: " . $c->req->url->path . ")");
    $c->res->code(500);
    $c->res->headers->content_type('application/json; charset=UTF-8');
    $c->render(json => { ok => 0, error => "$err" });
});

# Rate Limiting
hook before_dispatch => sub {
    my $c = shift;
    my $ip = client_ip($c);
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

# Authentifizierung
hook before_dispatch => sub {
    my $c = shift;
    my $ip = client_ip($c);
    return fail_json($c, "Forbidden IP $ip", 403) unless Net::CIDR::cidrlookup($ip, @acl_cidrs);
    my $hdr = $c->req->headers->header('X-API-Token');
    return fail_json($c, "Unauthorized: missing X-API-Token", 401) unless defined $hdr;
    return fail_json($c, "Unauthorized: invalid API token", 401) unless $hdr eq $api_token;
};

# Cache-Invalidierung
hook after_dispatch => sub {
    my $c = shift;
    if ($c->req->url->path =~ m{/autoreply/(server|user)/config$} && $c->req->method eq 'POST') {
        $Config = undef;
    }
};

# Housekeeping-Timer (alle 24 Stunden)
Mojo::IOLoop->recurring(86400 => sub {
    my $now = time;
    my $cutoff = $now - (3600 * 24);
    opendir(my $dh, $tmpDir) or do {
        app->log->error("Kann tmpDir nicht öffnen: $!");
        return;
    };
    while (my $file = readdir($dh)) {
        next if $file eq '.' || $file eq '..';
        my $path = File::Spec->catfile($tmpDir, $file);
        next unless -f $path;
        my $mtime = (stat($path))[9];
        if ($mtime < $cutoff) {
            unlink $path or app->log->warn("Kann $path nicht löschen: $!");
        }
    }
    closedir($dh);
    app->log->info("Housekeeping: Alte temporäre Dateien gelöscht.");
});

# =============================================
# ROUTEN
# =============================================

post '/autoreply/server/config' => sub {
    my $c = shift;
    my $up = $c->req->upload('config') or return fail_json($c, "No config uploaded", 400);
    my $f = File::Spec->catfile($configDir, 'autoreply_server.json');
    create_file_backup('server', $f) if -f $f;
    atomic_upload($up, $f) or return fail_json($c, "Upload fehlgeschlagen", 500);
    success_json($c, {});
};

get '/autoreply/server/config' => sub {
    my $c = shift;
    my $f = File::Spec->catfile($configDir, 'autoreply_server.json');
    return fail_json($c, "Config not found", 404) unless -f $f;
    $c->res->headers->content_disposition('attachment; filename="autoreply_server.json"');
    $c->reply->file($f);
};

post '/autoreply/user/config' => sub {
    my $c = shift;
    my $up = $c->req->upload('config') or return fail_json($c, "No config uploaded", 400);
    my $f = File::Spec->catfile($jsonDir, 'autoreply_user.json');
    create_file_backup('user', $f) if -f $f;
    atomic_upload($up, $f) or return fail_json($c, "Upload fehlgeschlagen", 500);
    success_json($c, {});
};

get '/autoreply/user/config' => sub {
    my $c = shift;
    my $f = File::Spec->catfile($jsonDir, 'autoreply_user.json');
    return fail_json($c, "Config not found", 404) unless -f $f;
    $c->res->headers->content_disposition('attachment; filename="autoreply_user.json"');
    $c->reply->file($f);
};

get '/autoreply/backups' => sub {
    my $c = shift;
    my @user;
    my @server;
    if (opendir(my $dh, $backupDir)) {
        @user = sort { $b cmp $a } grep { /^user_\d{8}_\d{6}\.json$/ } readdir($dh);
        @server = sort { $b cmp $a } grep { /^server_\d{8}_\d{6}\.json$/ } readdir($dh);
        closedir($dh);
    }
    success_json($c, { backups => [@user, @server] });
};

get '/autoreply/backup/*filename' => sub {
    my $c = shift;
    my $fn = $c->stash('filename') // '';
    $fn =~ s{[^a-zA-Z0-9_.-]}{}g;
    return fail_json($c, "Invalid filename", 400) unless $fn =~ /^(user|server)_\d{8}_\d{6}\.json$/;
    my $f = File::Spec->catfile($backupDir, $fn);
    return fail_json($c, "File not found", 404) unless -f $f;
    my $rel_path = File::Spec->abs2rel($f, $backupDir);
    return fail_json($c, "Invalid path", 400) if $rel_path =~ m{^\.\.}s;
    $c->res->headers->content_disposition("attachment; filename=\"$fn\"");
    $c->reply->file($f);
};

get '/autoreply/statslog' => sub {
    my $c = shift;
    return fail_json($c, "Stats-Log not found", 404) unless -f $statslog;
    chown_safe($statslog, $deployUID, $deployGID);
    $c->res->headers->content_disposition('attachment; filename="autoreply_stats.log"');
    $c->reply->file($statslog);
};

get '/health' => sub {
    my $c = shift;
    my %status;
    for my $p ($configDir, $jsonDir, $backupDir, $tmpDir, dirname($LOGFILE)) {
        $status{$p} = { exists => -e $p, writable => -w $p };
    }
    my @errors;
    for my $p (keys %status) {
        push @errors, "$p: " . join(', ', grep { !$status{$p}{$_} } keys %{$status{$p}}) unless $status{$p}{exists} && $status{$p}{writable};
    }
    return fail_json($c, "Check failed: " . join('; ', @errors), 503) if @errors;
    success_json($c, { status => 'ok', details => \%status });
};

any '/*whatever' => sub {
    my $c = shift;
    fail_json($c, "Unbekannte Route: " . $c->req->method . " " . $c->req->url->path, 404);
};

# =============================================
# SSL & START
# =============================================

if ($Config->{ssl_enable}) {
    my $ssl_cert = $Config->{ssl_cert_file} // die "ssl_cert_file fehlt in Config!";
    my $ssl_key  = $Config->{ssl_key_file}  // die "ssl_key_file fehlt in Config!";
    die "SSL-Zertifikat nicht lesbar: $ssl_cert\n" unless -r $ssl_cert;
    die "SSL-Key nicht lesbar: $ssl_key\n"   unless -r $ssl_key;
    die "SSL-Zertifikat ist leer: $ssl_cert\n" unless -s $ssl_cert;
    die "SSL-Key ist leer: $ssl_key\n"   unless -s $ssl_key;
}

my $listen_addr = $Config->{listen} // '0.0.0.0:5000';
my $listen_url = $Config->{ssl_enable}
    ? "https://$listen_addr?cert=$Config->{ssl_cert_file}&key=$Config->{ssl_key_file}"
    : "http://$listen_addr";

app->log->info("App gestartet auf $listen_url");
app->start('daemon', '-l', $listen_url);
