import "pe"

rule MAL_Compromised_Cert_CrazyEvilTraffer_Sectigo_250824C25A5D2BA93002CFAEDBFAF1BA {
   meta:
      description         = "Detects CrazyEvilTraffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-23"
      version             = "1.0"

      hash                = "c60f79c9fd9432f493256c8c5aa794dd141f9480c3d4fe187e4c48ceaf79088f"
      malware             = "CrazyEvilTraffer"
      malware_type        = "Loader"
      malware_notes       = "This malware is sold as a service. Frequently used with infostealers. See the following for more details: https://trac-labs.com/the-wagmi-manual-copy-paste-and-profit-2803a15bf540"

      signer              = "PAPER AND COTTON LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "25:08:24:c2:5a:5d:2b:a9:30:02:cf:ae:db:fa:f1:ba"
      cert_thumbprint     = "8A8945969807D26B12DB2BF83BBBB244AEFE3DB2"
      cert_valid_from     = "2025-10-23"
      cert_valid_to       = "2026-10-23"

      country             = "GB"
      state               = "Gloucestershire"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "25:08:24:c2:5a:5d:2b:a9:30:02:cf:ae:db:fa:f1:ba"
      )
}
