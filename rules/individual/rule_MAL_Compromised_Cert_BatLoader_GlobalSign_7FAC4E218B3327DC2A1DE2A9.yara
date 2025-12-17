import "pe"

rule MAL_Compromised_Cert_BatLoader_GlobalSign_7FAC4E218B3327DC2A1DE2A9 {
   meta:
      description         = "Detects BatLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-11-30"
      version             = "1.0"

      hash                = "7a11299b01c06a9ae30db6c51e59d9a5b8ab69e15db8f757718e5b52ce3184ed"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "Provizan Business Solutions, Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "7f:ac:4e:21:8b:33:27:dc:2a:1d:e2:a9"
      cert_thumbprint     = "418869222E0B6A46BED1AC26F91176AD79D2483E"
      cert_valid_from     = "2022-11-30"
      cert_valid_to       = "2023-12-01"

      country             = "CA"
      state               = "Ontario"
      locality            = "Oakville"
      email               = "???"
      rdn_serial_number   = "1008055-1"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "7f:ac:4e:21:8b:33:27:dc:2a:1d:e2:a9"
      )
}
