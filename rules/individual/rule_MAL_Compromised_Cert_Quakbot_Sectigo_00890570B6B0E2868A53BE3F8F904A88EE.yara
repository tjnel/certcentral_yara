import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00890570B6B0E2868A53BE3F8F904A88EE {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2021-11-11"
      version             = "1.0"

      hash                = "f5e0f08a97072dde8e5481e5cc645717055c821ce76d2d0d80e76a57b47f931b"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "JESEN LESS d.o.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee"
      cert_thumbprint     = "D74A465037EE5FB1D7D4C46A58E960459A3D0174"
      cert_valid_from     = "2021-11-11"
      cert_valid_to       = "2022-11-11"

      country             = "SI"
      state               = "Ljubljana"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee"
      )
}
