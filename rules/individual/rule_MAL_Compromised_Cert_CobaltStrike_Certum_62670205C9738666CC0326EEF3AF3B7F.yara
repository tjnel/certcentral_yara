import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Certum_62670205C9738666CC0326EEF3AF3B7F {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Certum)"
      author              = "CertGraveyard-YARA-Generator"
      reference           = "https://certgraveyard.org"
      date                = "2024-08-14"
      version             = "1.0"

      hash                = "a5442ceafa9bca74ae87bc82ab6387785f81501c5079cfc7b3d4db7003b42e89"
      malware             = "CobaltStrike"
      malware_type        = "Remote access tool"
      malware_notes       = "A commercial red-teaming product which is weaponized by a wide range of cybercriminals: https://malpedia.caad.fkie.fraunhofer.de/details/win.cobalt_strike"

      signer              = "Shenzhen Zhixinjie Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "62:67:02:05:c9:73:86:66:cc:03:26:ee:f3:af:3b:7f"
      cert_thumbprint     = "2CF10729CFE91555F26DC0ADF7743DD9738192CA"
      cert_valid_from     = "2024-08-14"
      cert_valid_to       = "2027-08-14"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Shenzhen"
      email               = "???"
      rdn_serial_number   = "91440300087758593U"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "62:67:02:05:c9:73:86:66:cc:03:26:ee:f3:af:3b:7f"
      )
}
