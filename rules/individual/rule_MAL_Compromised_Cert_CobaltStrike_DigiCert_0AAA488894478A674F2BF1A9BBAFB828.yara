import "pe"

rule MAL_Compromised_Cert_CobaltStrike_DigiCert_0AAA488894478A674F2BF1A9BBAFB828 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (DigiCert)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2019-10-23"
      version             = "1.0"

      hash                = "cac1ec8f6d73f15d1e6426c45b766bf61d89cc091e83d87be52287d26481b89f"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Appeon Inc."
      cert_issuer_short   = "DigiCert"
      cert_issuer         = "DigiCert SHA2 Assured ID Code Signing CA"
      cert_serial         = "0a:aa:48:88:94:47:8a:67:4f:2b:f1:a9:bb:af:b8:28"
      cert_thumbprint     = "DB41FA48A04A4058D15F5E3B6F320D8B53F1502A"
      cert_valid_from     = "2019-10-23"
      cert_valid_to       = "2022-01-29"

      country             = "US"
      state               = "California"
      locality            = "San Francisco"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "DigiCert SHA2 Assured ID Code Signing CA" and
         sig.serial == "0a:aa:48:88:94:47:8a:67:4f:2b:f1:a9:bb:af:b8:28"
      )
}
