import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_4152169F22454ED604D03555B7AFB175 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2020-07-27"
      version             = "1.0"

      hash                = "f3ebeeeba13c82daef9731a5f3e8dbe535e963f83e531918ba1a8904b094d3b8"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "SMACKTECH SOFTWARE LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo RSA Code Signing CA"
      cert_serial         = "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75"
      cert_thumbprint     = "0A05B51F64D9AB897484907BF3767CAABB1181D3"
      cert_valid_from     = "2020-07-27"
      cert_valid_to       = "2021-07-27"

      country             = "NZ"
      state               = "Auckland"
      locality            = "Auckland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo RSA Code Signing CA" and
         sig.serial == "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75"
      )
}
