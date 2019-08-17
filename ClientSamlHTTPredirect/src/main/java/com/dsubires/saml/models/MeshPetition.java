package com.dsubires.saml.models;

public class MeshPetition {

	DeviceStatus deviceStatus;
	String authcode;

	public DeviceStatus getDeviceStatus() {
		return deviceStatus;
	}

	public void setDeviceStatus(DeviceStatus deviceStatus) {
		this.deviceStatus = deviceStatus;
	}

	public String getAuthcode() {
		return authcode;
	}

	public void setAuthcode(String authcode) {
		this.authcode = authcode;
	}

	@Override
	public String toString() {
		return "MeshPetition [deviceStatus=" + deviceStatus + ", authcode=" + authcode + "]";
	}

}
