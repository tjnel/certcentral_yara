import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_70E1EBD170DB8102D8C28E58392E5632 {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-09-05"
      version             = "1.0"

      hash                = "c3cba8b38b1c9d930d6352803848798e6e9b8ef37e52523b97d5b94dd52fc732"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Equal Cash Technologies Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32"
      cert_thumbprint     = "345C2A6A717273E365F9302BC52CE065C50518E6"
      cert_valid_from     = "2020-09-05"
      cert_valid_to       = "2021-09-05"

      country             = "CA"
      state               = "Saskatchewan"
      locality            = "Regina"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32"
      )
}
