import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_33D83CD7A2AC80605D8A8CA249E95BAB {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-11-18"
      version             = "1.0"

      hash                = "1f79a38a04ecad2c2c27b92754f12764ea445e9c6f5346e52212cb105ce4bcbd"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BVH CAPITAL LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "33:d8:3c:d7:a2:ac:80:60:5d:8a:8c:a2:49:e9:5b:ab"
      cert_thumbprint     = "3CFB19D488672DA12A9F81F55E290C2967403EFA"
      cert_valid_from     = "2024-11-18"
      cert_valid_to       = "2025-11-23"

      country             = "CY"
      state               = "???"
      locality            = "Limassol"
      email               = "???"
      rdn_serial_number   = "HE 349945"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "33:d8:3c:d7:a2:ac:80:60:5d:8a:8c:a2:49:e9:5b:ab"
      )
}
