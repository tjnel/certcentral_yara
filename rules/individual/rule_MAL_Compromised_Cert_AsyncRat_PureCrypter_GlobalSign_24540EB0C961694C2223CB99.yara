import "pe"

rule MAL_Compromised_Cert_AsyncRat_PureCrypter_GlobalSign_24540EB0C961694C2223CB99 {
   meta:
      description         = "Detects AsyncRat,PureCrypter with compromised cert (GlobalSign)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-10-21"
      version             = "1.0"

      hash                = "f7d9a7964f72065aa9ad08dd0ba3df8abe095bae5d579919dab106f009c31d0c"
      malware             = "AsyncRat,PureCrypter"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Shantou Chenhui Industry Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "24:54:0e:b0:c9:61:69:4c:22:23:cb:99"
      cert_thumbprint     = "2523e6b059d1cd2e99387c8a9331fab477a1aed5cd0f88ffb6de782711694d5e"
      cert_valid_from     = "2024-10-21"
      cert_valid_to       = "2025-10-22"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shantou"
      email               = "???"
      rdn_serial_number   = "91440500733109863H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "24:54:0e:b0:c9:61:69:4c:22:23:cb:99"
      )
}
