import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_75A5A24642FCFDABE71A318AA28AA5BF {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-14"
      version             = "1.0"

      hash                = "875c1a2a1971d3f406c77195f9643a26514047e0d403b49d1a6345e2826f83ee"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "IT POLONIA SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "75:a5:a2:46:42:fc:fd:ab:e7:1a:31:8a:a2:8a:a5:bf"
      cert_thumbprint     = "FDFF8EA213A4E794D6871C380AE25075D051B1B5"
      cert_valid_from     = "2025-05-14"
      cert_valid_to       = "2026-05-14"

      country             = "PL"
      state               = "Lower Silesian Voivodeship"
      locality            = "Wrocław"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "75:a5:a2:46:42:fc:fd:ab:e7:1a:31:8a:a2:8a:a5:bf"
      )
}
