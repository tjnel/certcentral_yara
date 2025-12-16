import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Sectigo_0099527FB7264188F90B65ED893E220638 {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Sectigo)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2021-07-09"
      version             = "1.0"

      hash                = "9b2b902f5fd53b72cabfcc0e0191c876c92c1c748bcdbb7c00f9d62d7ba76914"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "PLAYWITH Inc."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:99:52:7f:b7:26:41:88:f9:0b:65:ed:89:3e:22:06:38"
      cert_thumbprint     = "839E615C9212B9017C93E8E9AFE50A39AFE48CD1"
      cert_valid_from     = "2021-07-09"
      cert_valid_to       = "2023-07-09"

      country             = "KR"
      state               = "Gyeonggi"
      locality            = "Seongnam"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:99:52:7f:b7:26:41:88:f9:0b:65:ed:89:3e:22:06:38"
      )
}
