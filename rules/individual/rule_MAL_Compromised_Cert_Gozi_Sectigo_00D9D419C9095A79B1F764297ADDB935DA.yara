import "pe"

rule MAL_Compromised_Cert_Gozi_Sectigo_00D9D419C9095A79B1F764297ADDB935DA {
   meta:
      description         = "Detects Gozi with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-10-25"
      version             = "1.0"

      hash                = "7b8ef3f064d0de0c27d56ff4df7d360f0d546d32aabbdf96a746bab5c84277ec"
      malware             = "Gozi"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OOO Nova soft"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:d9:d4:19:c9:09:5a:79:b1:f7:64:29:7a:dd:b9:35:da"
      cert_thumbprint     = "7D45EC21C0D6FD0EB84E4271655EB0E005949614"
      cert_valid_from     = "2020-10-25"
      cert_valid_to       = "2021-10-25"

      country             = "RU"
      state               = "???"
      locality            = "Belgorod"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:d9:d4:19:c9:09:5a:79:b1:f7:64:29:7a:dd:b9:35:da"
      )
}
