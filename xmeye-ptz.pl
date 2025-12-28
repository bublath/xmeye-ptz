#!/usr/bin/perl
use strict;
use warnings;

use LWP::UserAgent;
use JSON;
use Crypt::OpenSSL::Bignum;
use Crypt::CBC;
use MIME::Base64;
use Digest::MD5 qw(md5_hex);
use Getopt::Long;

# --- KONFIGURATION ---
my $ip       = "192.168.1.177";
my $user     = "admin";
my $password = "admin"; 
my $url      = "http://$ip/cgi-bin/login.cgi";
my $debug	 = 0;

GetOptions('ip=s' => \$ip, 'pw=s' => \$password, 'debug=s' => \$debug);

my $ua = LWP::UserAgent->new(timeout => 15);
$ua->default_header('Content-Type' => 'application/x-www-form-urlencoded;charset=UTF-8');
$ua->agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36");

# 1. Salt & Key holen
print "[*] Schritt 1: Hole Salt...\n" if $debug;
my $resp_salt = $ua->post($url, Content => '{"Name":"GetSalt"}');
my $data_salt = decode_json($resp_salt->decoded_content);
my $salt      = $data_salt->{Salt};
my ($n_hex, $e_hex) = split(',', $data_salt->{PublicKey});

# 2. RSA Mathematik vorbereiten
my $n_bn = Crypt::OpenSSL::Bignum->new_from_hex($n_hex);
my $e_bn = Crypt::OpenSSL::Bignum->new_from_hex($e_hex);
my $key_size_bytes = length(pack("H*", $n_hex)); # Sollte 128 sein

sub rsa_encrypt_manual {
    my ($text, $n_bn, $e_bn, $size) = @_;
    
    # PKCS#1 v1.5 Padding: 00 02 [RANDOM] 00 [DATA]
    my $pad_len = $size - length($text) - 3;
    my $padded = pack("C*", 0, 2);
    #my $padded = pack("C*", 2); #TEST
    for (1..$pad_len) {
        $padded .= pack("C", int(rand(254)) + 1);
    }
    $padded .= pack("C", 0) . $text;

    my $m_bn = Crypt::OpenSSL::Bignum->new_from_bin($padded);
    my $ctx  = Crypt::OpenSSL::Bignum::CTX->new();
    my $c_bn = $m_bn->mod_exp($e_bn, $n_bn, $ctx);
    
    # Hex-Konvertierung mit exakter Längenauffüllung
    my $hex = $c_bn->to_hex;
    $hex = "0$hex" if length($hex) % 2 != 0;
    $hex = ("00" x ($size - (length($hex)/2))) . $hex;
    return $hex;
}

# 3. Passwort Hashing (Exakt nach class.js)
my $pw_md5 = md5_hex($password); # Nur einfacher MD5!

# 4. Signatur & Felder vorbereiten
# Falls Ihr Browser-Log am Anfang des Strings etwas wie "GIGA_" zeigt, 
# muss das in den Header. Meistens ist er leer: ""
my $oemHeader = ""; 
my $sign_raw = $oemHeader . $salt . $pw_md5;

# VERK: 48 Zufallsbytes als Hex (96 Zeichen)
my $verk_raw = "";
for (1..48) { $verk_raw .= sprintf("%02x", int(rand(256))); }

# DTAK: 16 zufällige ASCII Zeichen (für den späteren AES-Kanal)
my $dtak_raw = join('', map { (0..9, 'a'..'z', 'A'..'Z')[rand 62] } 1..16);

# 5. Alles mit RSA verschlüsseln
my $verk_hex = rsa_encrypt_manual($verk_raw, $n_bn, $e_bn, $key_size_bytes);
my $dtak_hex = rsa_encrypt_manual($dtak_raw, $n_bn, $e_bn, $key_size_bytes);
my $user_hex = rsa_encrypt_manual($user,     $n_bn, $e_bn, $key_size_bytes);
my $sign_hex = rsa_encrypt_manual($sign_raw, $n_bn, $e_bn, $key_size_bytes);



# 6. Login JSON erstellen
my $login_json_obj = {
    "Name" => "Login",
    "LoginEncryptionType" => "RSA",
    "VERK" => $verk_hex,
    "DTAK" => $dtak_hex,
    "User" => $user_hex,
    "Sign" => $sign_hex, # Jetzt ebenfalls 256 Zeichen
    "Salt" => $salt
};

my $json_payload = encode_json($login_json_obj);

# Debugging: Prüfen der Längen
print "[DEBUG] Länge VERK: " . length($verk_hex) . "\n" if $debug;
print "[DEBUG] Länge Sign: " . length($sign_hex) . "\n" if $debug;


print "--- GESENDETES JSON ---\n" if $debug;
print $json_payload . "\n" if $debug;
print "-----------------------\n" if $debug;

# 7. Senden
my $resp_login = $ua->post($url, Content => $json_payload);
print "[*] Antwort der Kamera: " . $resp_login->decoded_content . "\n" if $debug;

my $sessiondata = decode_json($resp_login->decoded_content);
my $session_id      = $sessiondata->{SessionID};

my $cipher = Crypt::CBC->new(
    -key         => $dtak_raw,      # Dein 16-Byte Klartext-Schlüssel (aus Schritt 4/5)
    -cipher      => 'OpenSSL::AES', # Nutzt das AES-Modul
    -iv          => ("\0" x 16),    # Initialisierungsvektor: 16 Null-Bytes (Standard bei XMeye)
    -header      => 'none',         # Kein OpenSSL-Header (Salting) im Body
    -padding     => 'standard',     # PKCS#7 / PKCS#5 Padding
    -keysize     => 16,             # 128 Bit
    -literal_key => 1               # WICHTIG: Nutzt den String direkt als Key
);

# --- PTZ KONFIGURATION ---
my $ptz_url = "http://$ip/cgi-bin/opptz.cgi"; # Meist opera.cgi für PTZ

# Funktion zum Senden eines PTZ-Kommandos
sub send_ptz_fixed {
    my ($preset) = @_;
    # Bewegung z.B. Links:
    #"Command":"DirectionLeft",
	#"Preset":-1,
	#"Step":5

    my $ptz_data = {
        "Name" => "OPPTZControl",
        "SessionID" => $session_id, # Muss "0x" + 8-stellig Hex sein
		"Salt" => $salt,
        "OPPTZControl" => {
            "Command" => "GotoPreset",
            "Parameter" => {
                "AUX" => { "Number" => 0, "Status" => "On" },
                "Channel" => "0",
                "MenuOpts" => "Enter",
                "POINT" => { "bottom" => 0, "left" => 0, "right" => 0, "top" => 0 },
                "Pattern" => "SetBegin",
                "Preset" => $preset,
                "Step" => 0,
                "Tour" => 0
            }
        }
    };

my $json_string = encode_json($ptz_data);
my $padded_json = $json_string . "\0";

my $binary_encrypted = $cipher->encrypt($padded_json);
my $payload_b64 = encode_base64($binary_encrypted, "");

    # 5. Senden an opptz.cgi
    my $req = HTTP::Request->new(POST => "http://$ip/cgi-bin/opptz.cgi");
    $req->header('Content-Type' => 'text/plain;charset=UTF-8');
    $req->header('X-Requested-With' => 'XMLHttpRequest');

    $req->header('Cookie' => "Language=English; User=admin");
    $req->content($payload_b64);

    my $resp = $ua->request($req);
	
	# 1. Den Base64-Inhalt aus der Antwort holen
	my $raw_b64 = $resp->content;

	# 2. Einen speziellen "Raw-Decoder" ohne Padding nutzen, da die Antwort sonst manchmal abgeschnitten wird
	my $raw_cipher = Crypt::CBC->new(
    -key         => $dtak_raw,      # Dein aktueller Session-Key
    -cipher      => 'OpenSSL::AES',
    -iv          => ("\0" x 16),
    -header      => 'none',
    -padding     => 'none',         # WICHTIG: Kein automatisches Padding-Handling
    -keysize     => 16,
    -literal_key => 1
	);

	# 3. Dekodieren und manuell säubern
	my $binary = decode_base64($raw_b64);
	my $decrypted = $raw_cipher->decrypt($binary);

	# Entferne Null-Bytes oder Steuerzeichen am Ende, die durch fehlendes Padding entstehen
	$decrypted =~ s/[\x00-\x1F]+$//; 

	print "Antwort: $decrypted\n" if $debug;
	
}

# Aufruf für Preset 0:
send_ptz_fixed(1);
