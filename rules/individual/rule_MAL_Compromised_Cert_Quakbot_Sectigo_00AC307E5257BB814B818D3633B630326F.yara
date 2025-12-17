import "pe"

rule MAL_Compromised_Cert_Quakbot_Sectigo_00AC307E5257BB814B818D3633B630326F {
   meta:
      description         = "Detects Quakbot with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-11-23"
      version             = "1.0"

      hash                = "3b2e8af68cd45ca960f18b429395e701b650e7d603060282994feb9d01c90852"
      malware             = "Quakbot"
      malware_type        = "Initial access tool"
      malware_notes       = "This malware originated as a banking trojan and then became a initial access tool used by ransomware gangs."

      signer              = "Aqua Direct s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f"
      cert_thumbprint     = "4D6A089EC4EDCAC438717C1D64A8BE4EF925A9C6"
      cert_valid_from     = "2020-11-23"
      cert_valid_to       = "2021-11-23"

      country             = "CZ"
      state               = "???"
      locality            = "Brno"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f"
      )
}
