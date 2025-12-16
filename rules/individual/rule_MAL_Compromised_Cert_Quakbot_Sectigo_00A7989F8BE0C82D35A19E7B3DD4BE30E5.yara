import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00A7989F8BE0C82D35A19E7B3DD4BE30E5 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-22"
      version             = "1.0"

      hash                = "8b49bc1afd15dcc2bcc23b7637d58aca9a17b5b8a9e66ebdd109200fda384f0e"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Instamix Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
      cert_thumbprint     = "3593F02EB856F36BE77458777C86028DB5BD7588"
      cert_valid_from     = "2020-08-22"
      cert_valid_to       = "2021-08-22"

      country             = "IE"
      state               = "Dublin"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
      )
}
