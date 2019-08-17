package com.dsubires.saml.models;

/**
 * 
 * POJO. Represents a tuple inserted in elasticsearch by the devices.
 * 
 * @author David Subires
 *
 */
public class DeviceStatus implements java.io.Serializable {

	private static final long serialVersionUID = 1030303L;

	private String device;
	private Integer temperature;

	public DeviceStatus() {
		super();
		device = null;
		temperature = null;
	}

	public String getDevice() {
		return device;
	}

	public void setDevice(String device) {
		this.device = device;
	}

	public Integer getTemperature() {
		return temperature;
	}

	public void setTemperature(Integer temperature) {
		this.temperature = temperature;
	}

	@Override
	public String toString() {
		return "DeviceStatus [device=" + device + ", temperature=" + temperature + "]";
	}


}