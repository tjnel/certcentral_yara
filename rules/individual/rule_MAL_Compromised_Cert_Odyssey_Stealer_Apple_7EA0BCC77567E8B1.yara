import "pe"

rule MAL_Compromised_Cert_Odyssey_Stealer_Apple_7EA0BCC77567E8B1 {
   meta:
      description         = "Detects Odyssey Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-15"
      version             = "1.0"

      hash                = "22840ea54fe4dd3608a8815e72b8c1d2632ff054472e1dde1e56de676e63d07c"
      malware             = "Odyssey Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alina Balaban"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "7e:a0:bc:c7:75:67:e8:b1"
      cert_thumbprint     = "3306A2C6130B04B1E18ECBF9BE5CFCDF697C32C4"
      cert_valid_from     = "2025-07-15"
      cert_valid_to       = "2027-02-01"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "7e:a0:bc:c7:75:67:e8:b1"
      )
}
