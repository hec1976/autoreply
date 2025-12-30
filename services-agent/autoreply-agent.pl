#!/usr/bin/env perl
use v5.20;
use strict;
use warnings;

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
use Fcntl qw(SEEK_SET);
use JSON::Validator;
use Mojo::Util qw(secure_compare);

umask 0007;

# Global variable for configuration (cached)
my $Config;

# ---------- Helpers ----------
sub ensure_dir {
    my ($path) = @_;
    return 1 unless $path;
    my $dir = -d $path ? $path : dirname($path);
    return 1 if -d $dir && -w $dir;
    eval { make_path($dir); 1 } or do {
        app->log->warn("Could not create directory: $path");
        return 0;
    };
    return 1;
}

sub chown_safe {
    my ($path, $uid, $gid) = @_;
    return 1 unless -e $path;
    eval { chown $uid, $gid, $path or die $!; 1 } or do {
        app->log->warn("chown failed for $path: $!");
        return 0;
    };
    return 1;
}

sub chmod_safe {
    my ($path, $mode) = @_;
    return 1 unless -e $path;
    eval { chmod $mode, $path or die $!; 1 } or do {
        app->log->warn("chmod failed for $path: $!");
        return 0;
    };
    return 1;
}

# ---------- Load config (with caching) ----------
sub load_config {
    return $Config if $Config;

    my $configfile = "$Bin/config.json";
    die "Config file $configfile missing!\n" unless -f $configfile;

    open my $fh, "<:encoding(UTF-8)", $configfile or die "Config not readable: $!";
    local $/;
    my $json = <$fh>;
    close $fh;

    my $config;
    eval { $config = decode_json($json); 1 } or die "Invalid config JSON ($configfile): $@\n";
    die "Config JSON is not an object\n" unless ref($config) eq 'HASH';

    # Set defaults
    $config->{maxUploadMB}        //= 25;
    $config->{fileMode_service}   //= '0660';
    $config->{fileMode_deploy}    //= '0660';
    $config->{tmpFileMode}        //= '0660';
    $config->{maxBackups}         //= 20;
    $config->{maxBackupAgeDays}   //= 30;
    $config->{allowed_ips}        //= ['127.0.0.1'];
    $config->{client_ip_header}   //= 'X-Forwarded-For';

    # CIDR validation
    my @acl_cidrs = ref $config->{allowed_ips} eq 'ARRAY'
        ? @{$config->{allowed_ips}}
        : split /\s*,\s*/, ($config->{allowed_ips} // '127.0.0.1');
    for my $cidr (@acl_cidrs) {
        die "Invalid CIDR notation: $cidr\n" unless Net::CIDR::cidrvalidate($cidr);
    }

    $Config = $config;
    return $Config;
}

# Load configuration
$Config = load_config();

# Upload limit
my $max_mb = $Config->{maxUploadMB} // 25;
my $max_bytes = $max_mb * 1024 * 1024;
$ENV{MOJO_MAX_MESSAGE_SIZE} = $max_bytes;
app->max_request_size($max_bytes);

# Environment token
my $api_token = $ENV{API_TOKEN} or die "ENV API_TOKEN is required!\n";

# Network/listen settings
my $LOGFILE     = $Config->{logfile} // '/var/log/mmbb/autoreply-agent.log';
my @acl_cidrs   = ref $Config->{allowed_ips} eq 'ARRAY'
    ? @{ $Config->{allowed_ips} }
    : split /\s*,\s*/, ($Config->{allowed_ips} // '127.0.0.1');

# Trusted proxies and client IP header from config
my @trusted_proxies = ();
if (ref($Config->{trusted_proxies}) eq 'ARRAY') {
    @trusted_proxies = @{ $Config->{trusted_proxies} };
} elsif (defined $Config->{trusted_proxies} && $Config->{trusted_proxies} ne '') {
    @trusted_proxies = split /\s*,\s*/, $Config->{trusted_proxies};
}
my @ip_headers = (
    $Config->{client_ip_header} // 'X-Forwarded-For',
    'X-Real-IP',
    'CF-Connecting-IP',
);

# Paths
my $configDir   = $Config->{configDir}   or die "configDir missing!";
my $jsonDir     = $Config->{jsonDir}     or die "jsonDir missing!";
my $templateDir = $Config->{templateDir} // '';
my $statslog    = $Config->{statslog}    or die "statslog missing!";
my $backupDir   = $Config->{backupDir}   or die "backupDir missing!";
my $tmpDir      = $Config->{tmpDir}      or die "tmpDir missing!";

# File modes
my $maxBackups      = $Config->{maxBackups}        // 20;
my $maxBackupAgeDays = $Config->{maxBackupAgeDays}  // 30;
my $fileModeService = oct($Config->{fileMode_service} // '0660');
my $fileModeDeploy  = oct($Config->{fileMode_deploy}  // '0660');
my $tmpFileMode     = oct($Config->{tmpFileMode}      // '0660');

# Deploy user/group
my $deployUser  = $Config->{deployUser}  or die "deployUser missing!";
my $deployGroup = $Config->{deployGroup} or die "deployGroup missing!";
my $deployUID   = getpwnam($deployUser)  // die "User $deployUser does not exist!";
my $deployGID   = getgrnam($deployGroup) // die "Group $deployGroup does not exist!";

# ---------- Ensure log directory ----------
ensure_dir(dirname($LOGFILE)) or die "Could not create log directory: " . dirname($LOGFILE) . "\n";

# Open log file and set permissions
open(my $lfh, ">>:encoding(UTF-8)", $LOGFILE) or die "Log file not writable: $LOGFILE ($!)\n";
close $lfh;
chmod_safe($LOGFILE, $fileModeService);
chown_safe($LOGFILE, $deployUID, $deployGID);

# Redirect Mojolicious logging to file
app->log->path($LOGFILE);
app->log->level('info');

app->hook(around_dispatch => sub {
    my ($next, $c) = @_;
    my $ok = eval { $next->(); 1 };
    return if $ok;
    my $err = $@ || 'Unknown error';
    app->log->error("Request failed: $err (Path: " . $c->req->url->path . ")");
    $c->res->code(500);
    $c->res->headers->content_type('application/json; charset=UTF-8');
    $c->render(json => { ok => 0, error => "Internal server error" });
});

# ---------- Ensure directories ----------
for my $p ($configDir, $jsonDir, $templateDir, dirname($statslog), $backupDir, $tmpDir) {
    next unless $p;
    unless (ensure_dir($p)) {
        app->log->error("Could not create directory: $p");
        die "Critical error: Directory $p missing or not creatable\n";
    }
}

# Set ownership for config-relevant assets
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

# ---------- JSON helpers ----------
sub fail_json {
    my ($c, $msg, $st) = @_;
    $st //= 400;
    app->log->error("$msg (Path: " . $c->req->url->path . ")");
    $c->render(json => { ok => 0, error => $msg, status => $st }, status => $st);
}

sub success_json {
    my ($c, $d, $st) = @_;
    $st //= 200;
    $d->{ok} = 1       unless exists $d->{ok};
    $d->{status} = $st unless exists $d->{status};
    app->log->info("Success: status=$st");
    $c->render(json => $d, status => $st);
}

# ---------- Atomic upload ----------
sub atomic_upload {
    my ($up, $dest) = @_;
    return 0 unless $up && $dest;

    # Check content type
    return 0 unless $up->headers->content_type && $up->headers->content_type eq 'application/json';

    my $tmp = sprintf "%s/upload_%d_%d_%d", $tmpDir, $$, time, int(rand(1e6));
    eval {
        ensure_dir($tmpDir) or die "tmpDir not present or not writable";
        $up->move_to($tmp) or die "move_to failed: " . $up->error;
        chmod_safe($tmp, $tmpFileMode);

        ensure_dir(dirname($dest)) or die "Target directory missing or not writable";
        if (!rename $tmp, $dest) {
            copy($tmp, $dest) or die "copy failed: $!";
            unlink $tmp or app->log->warn("Could not delete temporary file: $tmp");
        }

        chmod_safe($dest, $fileModeDeploy);
        chown_safe($dest, $deployUID, $deployGID);

        app->log->info("Upload saved: " . basename($dest) . " (Size: " . (-s $dest) . " bytes)");
        1;
    } or do {
        app->log->error("Upload failed: $@");
        unlink $tmp if -e $tmp;
        return 0;
    };
    return 1;
}

# ---------- Backups (async) ----------
sub create_file_backup {
    my ($kind, $source_file) = @_;
    return unless -f $source_file;

    Mojo::IOLoop->subprocess(
        sub {
            my $ts   = localtime->strftime('%Y%m%d_%H%M%S');
            my $dest = File::Spec->catfile($backupDir, "${kind}_${ts}.json");
            eval {
                ensure_dir($backupDir) or die "backupDir missing";
                copy($source_file, $dest) or die "copy failed: $!";
                chmod_safe($dest, $fileModeService);

                my @list = sort { $b cmp $a } bsd_glob("$backupDir/${kind}_*.json");
                my $now = time;
                for my $old (@list) {
                    my $mtime = (stat($old))[9];
                    my $age_days = int(($now - $mtime) / 86400);
                    if ($age_days > $maxBackupAgeDays || @list > $maxBackups) {
                        unlink $old or app->log->warn("Could not delete backup: " . basename($old));
                    }
                }
                1;
            } or app->log->error("Backup failed: $@");
        },
        sub {
            my ($subprocess, $err) = @_;
            if ($err) {
                app->log->error("Async backup failed: $err");
            } else {
                app->log->info("Async backup successful");
            }
        }
    );
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

# ---------- Auth hooks ----------
hook before_dispatch => sub {
    my $c = shift;

    my $ip = client_ip($c);
    unless (Net::CIDR::cidrlookup($ip, @acl_cidrs)) {
        app->log->warn("Forbidden request (IP not allowed)");
        return fail_json($c, "Forbidden", 403);
    }

    my $hdr = $c->req->headers->header('X-API-Token');
    return fail_json($c, "Unauthorized: missing X-API-Token", 401) unless defined $hdr;
    return fail_json($c, "Unauthorized: invalid API token", 401) unless secure_compare($hdr, $api_token);
};

# ---------- Cache invalidation ----------
hook after_dispatch => sub {
    my $c = shift;
    if ($c->req->url->path =~ m{/autoreply/(server|user)/config$} && $c->req->method eq 'POST') {
        $Config = undef;
    }
};

# ---------- Routes ----------
post '/autoreply/server/config' => sub {
    my $c = shift;
    my $up = $c->req->upload('config') or return fail_json($c, "No config uploaded", 400);
    my $f = File::Spec->catfile($configDir, 'autoreply_server.json');
    create_file_backup('server', $f) if -f $f;
    atomic_upload($up, $f) or return fail_json($c, "Upload failed", 500);
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
    atomic_upload($up, $f) or return fail_json($c, "Upload failed", 500);
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
    return fail_json($c, "Invalid filename", 400)
        unless $fn =~ /^(user|server)_\d{8}_\d{6}\.json$/;

    my $f = File::Spec->catfile($backupDir, $fn);
    return fail_json($c, "File not found", 404) unless -f $f;
    my $rel_path = File::Spec->abs2rel($f, $backupDir);
    return fail_json($c, "Invalid path", 400) if $rel_path =~ m{^\.\.}s;

    $c->res->headers->content_disposition("attachment; filename=\"$fn\"");
    $c->reply->file($f);
};

get '/autoreply/statslog' => sub {
    my $c = shift;
    return fail_json($c, "Stats log not found", 404) unless -f $statslog;
    chown_safe($statslog, $deployUID, $deployGID);
    $c->res->headers->content_disposition('attachment; filename="autoreply_stats.log"');
    $c->reply->file($statslog);
};

get '/health' => sub {
    my $c = shift;
    my %status;
    for my $p ($configDir, $jsonDir, $backupDir, $tmpDir, dirname($LOGFILE)) {
        $status{$p} = {
            exists => -e $p,
            writable => -w $p,
        };
    }
    my @errors;
    for my $p (keys %status) {
        push @errors, "$p: " . join(', ', grep { !$status{$p}{$_} } keys %{$status{$p}})
            unless $status{$p}{exists} && $status{$p}{writable};
    }
    return fail_json($c, "Check failed: " . join('; ', @errors), 503) if @errors;
    success_json($c, { status => 'ok', details => \%status });
};

any '/*whatever' => sub {
    my $c = shift;
    fail_json($c, "Unknown route", 404);
};

# ---------- SSL check ----------
if ($Config->{ssl_enable}) {
    my $ssl_cert = $Config->{ssl_cert_file} // die "ssl_cert_file missing in config!";
    my $ssl_key  = $Config->{ssl_key_file}  // die "ssl_key_file missing in config!";
    die "SSL certificate not readable: $ssl_cert\n" unless -r $ssl_cert;
    die "SSL key not readable: $ssl_key\n"   unless -r $ssl_key;
    die "SSL certificate is empty: $ssl_cert\n" unless -s $ssl_cert;
    die "SSL key is empty: $ssl_key\n"   unless -s $ssl_key;
}

# ---------- Start ----------
my $listen_addr = $Config->{listen} // '0.0.0.0:5000';
my $listen_url = $Config->{ssl_enable}
    ? "https://$listen_addr?cert=$Config->{ssl_cert_file}&key=$Config->{ssl_key_file}"
    : "http://$listen_addr";

app->log->info("App started");
app->start('daemon', '-l', $listen_url);
