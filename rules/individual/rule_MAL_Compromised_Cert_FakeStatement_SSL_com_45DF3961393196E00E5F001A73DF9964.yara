import "pe"

rule MAL_Compromised_Cert_FakeStatement_SSL_com_45DF3961393196E00E5F001A73DF9964 {
   meta:
      description         = "Detects FakeStatement with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-04"
      version             = "1.0"

      hash                = "7347b09c6e10e203ec36c39dfc8d711af0beedfd9af3b85970ad60529579d5f6"
      malware             = "FakeStatement"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Automyynti Last Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "45:df:39:61:39:31:96:e0:0e:5f:00:1a:73:df:99:64"
      cert_thumbprint     = "CF49802079B7856E88B5B62F5F01B761403AB41A"
      cert_valid_from     = "2025-08-04"
      cert_valid_to       = "2026-08-04"

      country             = "FI"
      state               = "Etelä-Pohjanmaa"
      locality            = "SEINÄJOKI"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "45:df:39:61:39:31:96:e0:0e:5f:00:1a:73:df:99:64"
      )
}
