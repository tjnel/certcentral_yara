import "pe"

rule MAL_Compromised_Cert_RemcosRAT_Sectigo_00FECC3B3C675F7FFD7DE22507F3FDACD7 {
   meta:
      description         = "Detects RemcosRAT with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-11-25"
      version             = "1.0"

      hash                = "3d4ffcd1cd594f452ad1c374933eea8dd36d21a6d01372cc7f1afc636d26fa72"
      malware             = "RemcosRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gromit Electronics Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:fe:cc:3b:3c:67:5f:7f:fd:7d:e2:25:07:f3:fd:ac:d7"
      cert_thumbprint     = "B505C82DDDE0F9D2AE5E14956A504B4346581BBF"
      cert_valid_from     = "2022-11-25"
      cert_valid_to       = "2023-11-25"

      country             = "GB"
      state               = "Gloucestershire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:fe:cc:3b:3c:67:5f:7f:fd:7d:e2:25:07:f3:fd:ac:d7"
      )
}
