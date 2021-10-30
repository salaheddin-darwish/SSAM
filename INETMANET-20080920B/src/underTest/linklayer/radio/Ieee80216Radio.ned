package inet.underTest.linklayer.radio;

simple Ieee80216Radio
{
    parameters:
        double channelNumber_WiMAX; // channel identifier
        double transmitterPower; // power used for transmission of messages (in mW)
        double bitrate; // (in bits/s)
        double thermalNoise; // base noise level (dBm)
        double standardabweichung;
        double snirThreshold; // if signal-noise ratio is below this threshold, frame is considered noise (in dB)
        double sensitivity; // received signals with power below sensitivity are ignored
    gates:
        input uppergateIn;   // from higher layer protocol (MAC)
        output uppergateOut; // to decider (decider connects to higher layer protocol, i.e. the MAC)
        input radioIn; // to receive frames (AirFrame) on the radio channel
}

