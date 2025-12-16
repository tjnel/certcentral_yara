import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_5BF5E37EE4A4884DE448DD9927225FD5 {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-25"
      version             = "1.0"

      hash                = "7e490768afc996d5735cc98b502896aface074564f81b3dc450665c4cf72446d"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ebire Software Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "5b:f5:e3:7e:e4:a4:88:4d:e4:48:dd:99:27:22:5f:d5"
      cert_thumbprint     = "E685831781E35ED0B9CA48DEAE938A7DD8006546"
      cert_valid_from     = "2025-09-25"
      cert_valid_to       = "2026-09-25"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "5b:f5:e3:7e:e4:a4:88:4d:e4:48:dd:99:27:22:5f:d5"
      )
}
