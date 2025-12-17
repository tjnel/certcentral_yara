import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_7E0CCDA0EF37ACEF6C2EBE4538627E5C {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-04"
      version             = "1.0"

      hash                = "dc062275af294c93bf891da3aa1445bb52433632e83c97d152d05f0aa3466650"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Orangetree B.V."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
      cert_thumbprint     = "A758D6799E218DD66261DC5E2E21791CBCCCD6CB"
      cert_valid_from     = "2020-11-04"
      cert_valid_to       = "2021-11-04"

      country             = "NL"
      state               = "???"
      locality            = "Etten-Leur"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
      )
}
