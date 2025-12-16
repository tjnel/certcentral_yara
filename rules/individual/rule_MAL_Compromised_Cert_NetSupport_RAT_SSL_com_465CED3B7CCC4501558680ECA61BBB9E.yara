import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_SSL_com_465CED3B7CCC4501558680ECA61BBB9E {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-27"
      version             = "1.0"

      hash                = "5b04d7fee45d12dd86decd6b8ee075e95b3f1d7d689df824df0bffdcf9c0b6c8"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This is a weaponised Remote Management and monitoring tool."

      signer              = "Dai Software Limited"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "46:5c:ed:3b:7c:cc:45:01:55:86:80:ec:a6:1b:bb:9e"
      cert_thumbprint     = "49CDFC26AE060028F5FEC00E18DC52540470A328"
      cert_valid_from     = "2024-06-27"
      cert_valid_to       = "2025-06-27"

      country             = "GB"
      state               = "Wales"
      locality            = "Talbot Green"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "46:5c:ed:3b:7c:cc:45:01:55:86:80:ec:a6:1b:bb:9e"
      )
}
