import "pe"

rule MAL_Compromised_Cert_Pikabot_SSL_com_5E90650175692086F73DD05EE14B3DA5 {
   meta:
      description         = "Detects Pikabot with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-26"
      version             = "1.0"

      hash                = "fafdd87991351ff0fa2b888a9d22fc058f1a08a6c08651d7ee0164740c70ec51"
      malware             = "Pikabot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "4leaf Holding Corp."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5e:90:65:01:75:69:20:86:f7:3d:d0:5e:e1:4b:3d:a5"
      cert_thumbprint     = "94BACD94876552AA683B8D9E4772A0E37C985E30"
      cert_valid_from     = "2024-01-26"
      cert_valid_to       = "2025-01-25"

      country             = "CA"
      state               = "Alberta"
      locality            = "Edmonton"
      email               = "???"
      rdn_serial_number   = "1017531-5"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5e:90:65:01:75:69:20:86:f7:3d:d0:5e:e1:4b:3d:a5"
      )
}
