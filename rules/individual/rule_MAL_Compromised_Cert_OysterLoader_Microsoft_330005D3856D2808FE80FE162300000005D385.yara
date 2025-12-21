import "pe"

rule MAL_Compromised_Cert_OysterLoader_Microsoft_330005D3856D2808FE80FE162300000005D385 {
   meta:
      description         = "Detects OysterLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-18"
      version             = "1.0"

      hash                = "80a699d47def71f6ac0fa622a5f0b068d3ffcdb031749a4adc690fe2779ebc77"
      malware             = "OysterLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This version of OysterLoader was disguised as an AI application. It installs a scheduled task which loads the Supper backdoor."

      signer              = "ACCENT DESIGN INC."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:d3:85:6d:28:08:fe:80:fe:16:23:00:00:00:05:d3:85"
      cert_thumbprint     = "D24CA9DB911E6F387845D1684B7300CDB757D19F"
      cert_valid_from     = "2025-12-18"
      cert_valid_to       = "2025-12-21"

      country             = "CA"
      state               = "Québec"
      locality            = "Saint-Lambert"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:d3:85:6d:28:08:fe:80:fe:16:23:00:00:00:05:d3:85"
      )
}
