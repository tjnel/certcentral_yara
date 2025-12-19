import "pe"

rule MAL_Compromised_Cert_BaoLoader_Apple_2A7318646A5E64C0 {
   meta:
      description         = "Detects BaoLoader with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-03"
      version             = "1.0"

      hash                = "9fe25221834537c56e3514460f2c42ae0415ca40449ca7b71cebd8bd0445eefd"
      malware             = "BaoLoader"
      malware_type        = "Trojan"
      malware_notes       = "Certificate was identified while investigating BaoLoader malware. File was identified as a ManualFinder.pkg for MacOS."

      signer              = "IENGINEERING PRIVATE LIMITED"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "2a:73:18:64:6a:5e:64:c0"
      cert_thumbprint     = "9E8EABB61C444DB5C5D44C924B03AFC9670407BC"
      cert_valid_from     = "2025-06-03"
      cert_valid_to       = "2027-02-01"

      country             = "US"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "2a:73:18:64:6a:5e:64:c0"
      )
}
