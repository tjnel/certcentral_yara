import "pe"

rule MAL_Compromised_Cert_Stealc_HijackLoader_GlobalSign_3A352958B8D4FDAFE1C6B8E8 {
   meta:
      description         = "Detects Stealc, HijackLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-16"
      version             = "1.0"

      hash                = "393943bd4908cb8da49927fee8ddc6d7f14cc0948e77988e32f3cdd74c5ae118"
      malware             = "Stealc, HijackLoader"
      malware_type        = "Infostealer"
      malware_notes       = "A popular and customizable infostealler that can also function as a loader: https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-1/"

      signer              = "UTTAM AGRITECH PRIVATE LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "3a:35:29:58:b8:d4:fd:af:e1:c6:b8:e8"
      cert_thumbprint     = "5e253b7620940a7d4ec389daa83be219b290f887874da6aa4dc02260ae27e715"
      cert_valid_from     = "2025-07-16"
      cert_valid_to       = "2026-07-17"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "uttamagritechindia@gmail.com"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3a:35:29:58:b8:d4:fd:af:e1:c6:b8:e8"
      )
}
