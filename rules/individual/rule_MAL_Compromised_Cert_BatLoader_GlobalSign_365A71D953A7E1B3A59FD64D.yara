import "pe"

rule MAL_Compromised_Cert_BatLoader_GlobalSign_365A71D953A7E1B3A59FD64D {
   meta:
      description         = "Detects BatLoader with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-12-24"
      version             = "1.0"

      hash                = "15c39d2084e399b4a0126c0b1026bd2342f8dc5d812cf0d0caae8e35ee689407"
      malware             = "BatLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "See this article to learn more about Batloader: https://blogs.vmware.com/security/2022/11/batloader-the-evasive-downloader-malware.html"

      signer              = "MK Investment Properties Inc."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "36:5a:71:d9:53:a7:e1:b3:a5:9f:d6:4d"
      cert_thumbprint     = "C8A2E1AE0CA91D1CDFA83C4A4F6C880FA9738198"
      cert_valid_from     = "2021-12-24"
      cert_valid_to       = "2022-12-25"

      country             = "CA"
      state               = "Ontario"
      locality            = "Ashton"
      email               = "Chloe.Miller@globaltreeinvestments.com"
      rdn_serial_number   = "10044873"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "36:5a:71:d9:53:a7:e1:b3:a5:9f:d6:4d"
      )
}
