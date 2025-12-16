import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7D0CDDA8F234B4F4B00E0D5448B72675 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2025-03-13"
      version             = "1.0"

      hash                = "59b483eb9fb0cab4d97e33c083bcf25f9cb5fff771aa08cec50d6dab7c6e21b4"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "EVRO DERMA KOSMETIKS, OSOO"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7d:0c:dd:a8:f2:34:b4:f4:b0:0e:0d:54:48:b7:26:75"
      cert_thumbprint     = "702A511D966AAD4A5CB63F766F7EB4837FE18B59"
      cert_valid_from     = "2025-03-13"
      cert_valid_to       = "2026-03-13"

      country             = "KG"
      state               = "???"
      locality            = "Bishkek"
      email               = "???"
      rdn_serial_number   = "210568-3301-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7d:0c:dd:a8:f2:34:b4:f4:b0:0e:0d:54:48:b7:26:75"
      )
}
