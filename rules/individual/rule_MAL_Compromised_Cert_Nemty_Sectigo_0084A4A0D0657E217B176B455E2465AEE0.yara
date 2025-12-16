import "pe"

rule MAL_Compromised_Cert_Nemty_Sectigo_0084A4A0D0657E217B176B455E2465AEE0 {
   meta:
      description         = "Detects Nemty with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-03-23"
      version             = "1.0"

      hash                = "511fee839098dfa28dd859ffd3ece5148be13bfb83baa807ed7cac2200103390"
      malware             = "Nemty"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "AATB ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0"
      cert_thumbprint     = "AD2496D9F9A1E86FB8D7E4C2762C6035B883F3A4"
      cert_valid_from     = "2021-03-23"
      cert_valid_to       = "2022-03-23"

      country             = "DK"
      state               = "???"
      locality            = "Aalborg SØ"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0"
      )
}
