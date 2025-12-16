import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_69A72F5591AD78A0825FBB9402AB9543 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2022-02-16"
      version             = "1.0"

      hash                = "80b5ed7b12e236b36722bed7293766a4a7307a948c841eef8585fd8ae4813608"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "PUSH BANK LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43"
      cert_thumbprint     = "094B5650BA763AD448C958F873E37DC067B85645"
      cert_valid_from     = "2022-02-16"
      cert_valid_to       = "2023-02-16"

      country             = "GB"
      state               = "Cumbria"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43"
      )
}
