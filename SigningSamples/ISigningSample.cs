﻿using System;
using System.Collections.Generic;
using System.Text;

namespace SigningSamples
{
    interface ISigningSample
    {
        public void ReadCertification(string pfxPath);

        public string Sign(string input);

        public bool Verify(string signedInput);
    }
}
