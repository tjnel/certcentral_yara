import "pe"

rule MAL_Compromised_Cert_Oyster_GlobalSign_48CC67779AA54699C6B1D7FE {
   meta:
      description         = "Detects Oyster with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-02"
      version             = "1.0"

      hash                = "b61b51ba6ad7f7fe6465093a7c3f3f10d1079159febe33efb26fd64fa80408f1"
      malware             = "Oyster"
      malware_type        = "Initial access tool"
      malware_notes       = "An initial access tool used by the Rhysida ransomware gang. See https://expel.com/blog/certified-oysterloader-tracking-rhysida-ransomware-gang-activity-via-code-signing-certificates/ for more details."

      signer              = "LLC Globalnerudpostavka"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "48:cc:67:77:9a:a5:46:99:c6:b1:d7:fe"
      cert_thumbprint     = "48D6D6529B0B98FD7CEAC4BF044519098ACE9213"
      cert_valid_from     = "2025-08-02"
      cert_valid_to       = "2026-04-11"

      country             = "RU"
      state               = "Moscow"
      locality            = "Kommunarka"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "48:cc:67:77:9a:a5:46:99:c6:b1:d7:fe"
      )
}
