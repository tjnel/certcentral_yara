import "pe"

rule MAL_Compromised_Cert_Hive_Sectigo_00E9268ED63A7D7E9DFD40A664DDFBAF18 {
   meta:
      description         = "Detects Hive with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2022-03-15"
      version             = "1.0"

      hash                = "f4a39820dbff47fa1b68f83f575bc98ed33858b02341c5c0464a49be4e6c76d3"
      malware             = "Hive"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Casta, s.r.o."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18"
      cert_thumbprint     = "6D798B3C3A0A85E16F98B05D6E51B66838A56DFF"
      cert_valid_from     = "2022-03-15"
      cert_valid_to       = "2023-03-15"

      country             = "SK"
      state               = "Bratislavský kraj"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18"
      )
}
