import "pe"

rule MAL_Compromised_Cert_PDFast_GlobalSign_7492A1D8A6E9489CA1872F02 {
   meta:
      description         = "Detects PDFast with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-02"
      version             = "1.0"

      hash                = "f87f43af104abbb84208b97877eaa5e34b657ab1c381c458bcb805801ff3cc03"
      malware             = "PDFast"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "THE-SHOP STOP LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "74:92:a1:d8:a6:e9:48:9c:a1:87:2f:02"
      cert_thumbprint     = "3ACF161DC680CB52BDCF3227248E933DE361BD48"
      cert_valid_from     = "2024-10-02"
      cert_valid_to       = "2025-10-03"

      country             = "US"
      state               = "Florida"
      locality            = "Saint Petersburg"
      email               = "farhadikhlaq483@gmail.com"
      rdn_serial_number   = "L23000038092"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "74:92:a1:d8:a6:e9:48:9c:a1:87:2f:02"
      )
}
