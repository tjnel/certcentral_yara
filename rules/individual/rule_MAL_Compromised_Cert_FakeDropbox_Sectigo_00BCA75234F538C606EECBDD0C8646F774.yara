import "pe"

rule MAL_Compromised_Cert_FakeDropbox_Sectigo_00BCA75234F538C606EECBDD0C8646F774 {
   meta:
      description         = "Detects FakeDropbox with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-30"
      version             = "1.0"

      hash                = "477b70c677c0a3dd145463957a2e737a36c90b3a860b155a4c1c6ab7610b0f99"
      malware             = "FakeDropbox"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BSD TASIMACILIK TURIZM INSAAT SANAYI TICARET LIMITED SIRKETI"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:bc:a7:52:34:f5:38:c6:06:ee:cb:dd:0c:86:46:f7:74"
      cert_thumbprint     = "DDC8F9ECE2C7B4176BF9BEF770A2FA432FDBB227"
      cert_valid_from     = "2026-01-30"
      cert_valid_to       = "2027-01-30"

      country             = "TR"
      state               = "İstanbul"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "1017528"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:bc:a7:52:34:f5:38:c6:06:ee:cb:dd:0c:86:46:f7:74"
      )
}
