#!/usr/bin/env perl
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
use Log::Log4perl qw(:easy);
use File::Path qw(make_path);
use Fcntl qw(SEEK_SET);

umask 0007;

# Logger wird spaeter initialisiert, aber wir deklarieren ihn hier,
# damit Helper ihn optional nutzen koennen.
my $logger;

# ---------- helpers (muessen vor Log4perl init verfuegbar sein) ----------
sub ensure_dir {
  my ($path) = @_;
  return 1 unless $path;
  my $dir = -d $path ? $path : dirname($path);
  return 1 if -d $dir;
  eval { make_path($dir); 1 } or return 0;
  return 1;
}

sub chown_safe {
  my ($path, $uid, $gid) = @_;
  return 1 unless -e $path;
  eval { chown $uid, $gid, $path or die $!; 1 } or do {
    if ($logger) { $logger->warn("chown fehlgeschlagen fuer $path: $!"); }
    else { warn "WARN chown fehlgeschlagen fuer $path: $!\n"; }
    return 0;
  };
  return 1;
}

sub chmod_safe {
  my ($path, $mode) = @_;
  return 1 unless -e $path;
  eval { chmod $mode, $path or die $!; 1 } or do {
    if ($logger) { $logger->warn("chmod fehlgeschlagen fuer $path: $!"); }
    else { warn "WARN chmod fehlgeschlagen fuer $path: $!\n"; }
    return 0;
  };
  return 1;
}

# ---------- config laden (flach) ----------
my $configfile = "$Bin/config.json";
die "Config $configfile fehlt!\n" unless -f $configfile;

open my $fh, "<:encoding(UTF-8)", $configfile or die "Config nicht lesbar: $!";
local $/;
my $json = <$fh>;
close $fh;

my $Config;
eval { $Config = decode_json($json); 1 }
  or die "Config JSON ungueltig ($configfile): $@\n";
die "Config JSON ist kein Objekt\n" unless ref($Config) eq 'HASH';

# Upload Limit
my $max_mb = $Config->{maxUploadMB} // 25;
my $max_bytes = $max_mb * 1024 * 1024;
$ENV{MOJO_MAX_MESSAGE_SIZE} = $max_bytes;
app->max_request_size($max_bytes);

# env token
my $api_token = $ENV{API_TOKEN} or die "ENV API_TOKEN ist erforderlich!\n";

# net / listen
my $LOGFILE     = $Config->{logfile} // '/var/log/mmbb/autoreply-agent.log';
my @acl_cidrs   = ref $Config->{allowed_ips} eq 'ARRAY'
  ? @{ $Config->{allowed_ips} }
  : split /\s*,\s*/, ($Config->{allowed_ips} // '127.0.0.1');

# Trusted Proxies und Client IP Header aus Config
my @trusted_proxies = ();
if (ref($Config->{trusted_proxies}) eq 'ARRAY') {
  @trusted_proxies = @{ $Config->{trusted_proxies} };
} elsif (defined $Config->{trusted_proxies} && $Config->{trusted_proxies} ne '') {
  @trusted_proxies = split /\s*,\s*/, $Config->{trusted_proxies};
}
my $client_ip_header = $Config->{client_ip_header} // 'X-Forwarded-For';

my $listen_addr = $Config->{listen} // '0.0.0.0:5000';
my $ssl_enable  = $Config->{ssl_enable} ? 1 : 0;
my $ssl_cert    = $Config->{ssl_cert_file} // '';
my $ssl_key     = $Config->{ssl_key_file}  // '';

# pfade
my $configDir   = $Config->{configDir}   or die "configDir fehlt!";
my $jsonDir     = $Config->{jsonDir}     or die "jsonDir fehlt!";
my $templateDir = $Config->{templateDir} // '';
my $statslog    = $Config->{statslog}    or die "statslog fehlt!";
my $backupDir   = $Config->{backupDir}   or die "backupDir fehlt!";
my $tmpDir      = $Config->{tmpDir}      or die "tmpDir fehlt!";

# filemodes
my $maxBackups      = $Config->{maxBackups}        // 20;
my $fileModeService = oct($Config->{fileMode_service} // '0660');
my $fileModeDeploy  = oct($Config->{fileMode_deploy}  // '0660');
my $tmpFileMode     = oct($Config->{tmpFileMode}      // '0660');

# deploy owner/group
my $deployUser  = $Config->{deployUser}  or die "deployUser fehlt!";
my $deployGroup = $Config->{deployGroup} or die "deployGroup fehlt!";
my $deployUID   = getpwnam($deployUser)  // die "Benutzer $deployUser existiert nicht!";
my $deployGID   = getgrnam($deployGroup) // die "Gruppe $deployGroup existiert nicht!";

# ---------- Logdir vor Log4perl init sicherstellen ----------
ensure_dir(dirname($LOGFILE)) or die "Konnte Logdir nicht anlegen: " . dirname($LOGFILE) . "\n";

open(my $lfh, ">>:encoding(UTF-8)", $LOGFILE) or die "Logfile nicht schreibbar: $LOGFILE ($!)\n";
close $lfh;

# Rechte/Owner bereits jetzt setzen, damit Log4perl sauber schreiben kann
chmod_safe($LOGFILE, $fileModeService);
chown_safe($LOGFILE, $deployUID, $deployGID);

# ---------- logging ----------
my $log_conf = qq(
  log4perl.rootLogger             = INFO, File, Screen
  log4perl.appender.File          = Log::Log4perl::Appender::File
  log4perl.appender.File.filename = $LOGFILE
  log4perl.appender.File.syswrite = 1
  log4perl.appender.File.layout   = Log::Log4perl::Layout::PatternLayout
  log4perl.appender.File.layout.ConversionPattern = [%d] [%p] %m%n
  log4perl.appender.Screen        = Log::Log4perl::Appender::Screen
  log4perl.appender.Screen.stderr = 1
  log4perl.appender.Screen.layout = Log::Log4perl::Layout::PatternLayout
  log4perl.appender.Screen.layout.ConversionPattern = [%d] [%p] %m%n
);

Log::Log4perl::init(\$log_conf);
$logger = Log::Log4perl->get_logger();

app->hook(around_dispatch => sub {
  my ($next, $c) = @_;
  my $ok = eval { $next->(); 1 };
  return if $ok;
  my $err = $@ || 'Unknown error';
  $c->res->code(500);
  $c->res->headers->content_type('application/json; charset=UTF-8');
  $c->render(json => { ok => 0, error => "$err" });
});

# ---------- verzeichnisse sicherstellen ----------
for my $p ($configDir, $jsonDir, $templateDir, dirname($statslog), $backupDir, $tmpDir) {
  next unless $p;
  unless (ensure_dir($p)) {
    $logger->error("Konnte Verzeichnis nicht anlegen: $p");
  }
}

# Ownership nur fuer config relevante Assets
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
  my ($c,$msg,$st)=@_;
  $st//=400;
  $logger->error($msg);
  $c->render(json=>{ok=>0,error=>$msg,status=>$st},status=>$st);
}

sub success_json {
  my ($c,$d,$st)=@_;
  $st//=200;
  $d->{ok}=1       unless exists $d->{ok};
  $d->{status}=$st unless exists $d->{status};
  $logger->info("Erfolgreich: status=$st");
  $c->render(json=>$d,status=>$st);
}

# ---------- upload atomar ----------
sub atomic_upload {
  my ($up,$dest)=@_;
  return 0 unless $up && $dest;

  my $tmp = sprintf "%s/upload_%d_%d_%d", $tmpDir, $$, time, int(rand(1e6));
  eval {
    ensure_dir($tmpDir) or die "tmpDir nicht vorhanden";
    $up->move_to($tmp) or die "move_to fehlgeschlagen";
    chmod_safe($tmp, $tmpFileMode);

    ensure_dir(dirname($dest)) or die "Zielverzeichnis fehlt";
    if (!rename $tmp, $dest) {
      copy($tmp, $dest) or die "copy fehlgeschlagen: $!";
      unlink $tmp;
    }

    chmod_safe($dest, $fileModeDeploy);
    chown_safe($dest, $deployUID, $deployGID);

    $logger->info("Upload gespeichert: $dest");
    1;
  } or do {
    $logger->error("Upload fehlgeschlagen ($dest): $@");
    unlink $tmp if -e $tmp;
    return 0;
  };
  return 1;
}

# ---------- backups ----------
sub create_file_backup {
  my ($kind, $source_file) = @_;
  return unless -f $source_file;

  my $ts   = localtime->strftime('%Y%m%d_%H%M%S');
  my $dest = File::Spec->catfile($backupDir, "${kind}_${ts}.json");

  eval {
    ensure_dir($backupDir) or die "backupDir fehlt";
    copy($source_file, $dest) or die "copy fehlgeschlagen: $!";
    chmod_safe($dest, $fileModeService);

    my @list = sort { $b cmp $a } bsd_glob("$backupDir/${kind}_*.json");
    if (@list > $maxBackups) {
      for my $old (@list[$maxBackups .. $#list]) {
        unlink $old or $logger->warn("Kann Backup nicht loeschen $old: $!");
      }
    }
    1;
  } or $logger->error("Backup fehlgeschlagen: $@");

  return $dest;
}

sub client_ip {
  my ($c) = @_;
  my $rip = $c->tx->remote_address // '';

  return $rip unless @trusted_proxies;

  my $is_trusted = 0;
  for my $tp (@trusted_proxies) {
    next unless defined $tp && $tp ne '';
    if ($rip eq $tp) { $is_trusted = 1; last; }
  }
  return $rip unless $is_trusted;

  my $h = $c->req->headers->header($client_ip_header) // '';
  return $rip unless $h;

  my ($first) = split /\s*,\s*/, $h;
  $first //= '';
  $first =~ s/^\s+|\s+$//g;

  return $rip unless $first =~ /^[0-9a-fA-F:\.]+$/;

  return $first;
}

# ---------- hooks/auth ----------
hook before_dispatch => sub {
  my $c = shift;

  my $ip = client_ip($c);

  return fail_json($c, "Forbidden IP $ip", 403)
    unless Net::CIDR::cidrlookup($ip, @acl_cidrs);

  my $hdr = $c->req->headers->header('X-API-Token');
  return fail_json($c, "Unauthorized: missing X-API-Token", 401) unless defined $hdr;
  return fail_json($c, "Unauthorized: invalid API token", 401)   unless $hdr eq $api_token;
};

# ---------- routes ----------
post '/autoreply/server/config' => sub {
  my $c=shift;
  my $up=$c->req->upload('config') or return fail_json($c,"No config uploaded",400);
  my $f=File::Spec->catfile($configDir,'autoreply_server.json');
  create_file_backup('server', $f) if -f $f;
  atomic_upload($up,$f) or return fail_json($c,"Upload fehlgeschlagen",500);
  success_json($c,{});
};

get '/autoreply/server/config' => sub {
  my $c=shift;
  my $f=File::Spec->catfile($configDir,'autoreply_server.json');
  return fail_json($c,"Config not found",404) unless -f $f;
  $c->res->headers->content_disposition('attachment; filename="autoreply_server.json"');
  $c->reply->file($f);
};

post '/autoreply/user/config' => sub {
  my $c=shift;
  my $up=$c->req->upload('config') or return fail_json($c,"No config uploaded",400);
  my $f=File::Spec->catfile($jsonDir,'autoreply_user.json');
  create_file_backup('user', $f) if -f $f;
  atomic_upload($up,$f) or return fail_json($c,"Upload fehlgeschlagen",500);
  success_json($c,{});
};

get '/autoreply/user/config' => sub {
  my $c=shift;
  my $f=File::Spec->catfile($jsonDir,'autoreply_user.json');
  return fail_json($c,"Config not found",404) unless -f $f;
  $c->res->headers->content_disposition('attachment; filename="autoreply_user.json"');
  $c->reply->file($f);
};

get '/autoreply/backups' => sub {
  my $c=shift;
  my @user   = map { basename($_) } sort { $b cmp $a } bsd_glob("$backupDir/user_*.json");
  my @server = map { basename($_) } sort { $b cmp $a } bsd_glob("$backupDir/server_*.json");
  success_json($c,{ backups => [@user,@server] });
};

get '/autoreply/backup/*filename' => sub {
  my $c=shift;
  my $fn = $c->stash('filename') // '';
  $fn =~ s{[^a-zA-Z0-9_.-]}{}g;
  return fail_json($c,"Invalid filename",400)
    unless $fn =~ /^(user|server)_\d{8}_\d{6}\.json$/;
  my $f=File::Spec->catfile($backupDir,$fn);
  return fail_json($c,"File not found",404) unless -f $f;
  $c->res->headers->content_disposition("attachment; filename=\"$fn\"");
  $c->reply->file($f);
};

get '/autoreply/statslog' => sub {
  my $c=shift;
  return fail_json($c,"Stats-Log not found",404) unless -f $statslog;
  chown_safe($statslog, $deployUID, $deployGID);
  $c->res->headers->content_disposition('attachment; filename="autoreply_stats.log"');
  $c->reply->file($statslog);
};

get '/health' => sub {
  my $c = shift;
  my @paths = ($configDir, $jsonDir, $backupDir, $tmpDir);
  my @miss  = grep { !-e $_ } @paths;
  my @nowrt = grep { !-w $_ } grep { -d $_ } @paths;
  my @logdir = (dirname($LOGFILE));
  push @miss,  $LOGFILE unless -e $LOGFILE;
  push @nowrt, @logdir   if grep { !-w $_ } @logdir;
  return fail_json($c, "Check failed: missing=@miss no_write=@nowrt", 503) if @miss || @nowrt;
  success_json($c, { status => 'ok' });
};

any '/*whatever' => sub {
  my $c = shift;
  fail_json($c,"Unbekannte Route: ".$c->req->method." ".$c->req->url->path,404);
};

# ---------- start ----------
my $listen_url = ($ssl_enable && $ssl_cert && $ssl_key)
  ? "https://$listen_addr?cert=$ssl_cert&key=$ssl_key"
  : "http://$listen_addr";

$logger->info("App gestartet auf $listen_url");
app->start('daemon','-l',$listen_url);
