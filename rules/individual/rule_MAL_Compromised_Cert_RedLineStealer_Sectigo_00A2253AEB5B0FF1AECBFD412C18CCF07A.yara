import "pe"

rule MAL_Compromised_Cert_RedLineStealer_Sectigo_00A2253AEB5B0FF1AECBFD412C18CCF07A {
   meta:
      description         = "Detects RedLineStealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-08-27"
      version             = "1.0"

      hash                = "ae2ff54d0460f10178a7984924504119353fe27dd7c84f1166505593cb7e464b"
      malware             = "RedLineStealer"
      malware_type        = "Infostealer"
      malware_notes       = "A malware as a service infostealer: https://www.proofpoint.com/us/blog/threat-insight/new-redline-stealer-distributed-using-coronavirus-themed-email-campaign"

      signer              = "Gallopers Software Solutions Limited"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "00:a2:25:3a:eb:5b:0f:f1:ae:cb:fd:41:2c:18:cc:f0:7a"
      cert_thumbprint     = "B03DB8E908DCF0E00A5A011BA82E673D91524816"
      cert_valid_from     = "2020-08-27"
      cert_valid_to       = "2021-08-27"

      country             = "IE"
      state               = "Kildare"
      locality            = "Naas"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "00:a2:25:3a:eb:5b:0f:f1:ae:cb:fd:41:2c:18:cc:f0:7a"
      )
}
