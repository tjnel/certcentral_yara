import "pe"

rule MAL_Compromised_Cert_Latam_Banker_GlobalSign_11D212117C7C5ACC5954C910 {
   meta:
      description         = "Detects Latam Banker with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-29"
      version             = "1.0"

      hash                = "98a23d306c5169bc4b5772c7b946d61f2c9f552d63be7d88dd404b87e21d7626"
      malware             = "Latam Banker"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTWARE AFFAIR LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "11:d2:12:11:7c:7c:5a:cc:59:54:c9:10"
      cert_thumbprint     = "A872BE45D9552120C06E79D2A6532079AC89FD72"
      cert_valid_from     = "2024-07-29"
      cert_valid_to       = "2025-07-26"

      country             = "GB"
      state               = "Romney Marsh"
      locality            = "Dymchurch"
      email               = "admin@softwareaffairlimited.com"
      rdn_serial_number   = "09764500"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "11:d2:12:11:7c:7c:5a:cc:59:54:c9:10"
      )
}
