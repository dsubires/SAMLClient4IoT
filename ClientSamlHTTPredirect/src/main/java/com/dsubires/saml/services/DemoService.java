package com.dsubires.saml.services;

import java.util.Random;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import com.dsubires.saml.models.DeviceStatus;

@Service
public class DemoService {

	@Value("${mesh.host}")
	private String meshHost;
	private Logger logger = LogManager.getLogger("scheduledTask");
	@Autowired
	ClientService clientService;
	String[] devices = new String[] { "Device 1", "Device 2", "Device 3", "Device 4", "Device 5", "Device MESH" };

	/**
	 * 
	 * el dispositivo 1, que envía [20-60] peticiones de autenticación, se lanza
	 * cada 10 segundos. El 10% de las peticiones de autenticación serán intentos
	 * fallidos.
	 */
	@Scheduled(fixedDelay = 10000)
	public void device1demo() {
		logger.info("starting device 1 demo");

		int requests = (int) (Math.random() * ((60 - 20) + 1)) + 20;

		while (requests > 0) {

			if (Math.random() > 0.1d) {
				// login ok
				clientService.authentication();
			} else {
				// login ko
				clientService.authenticationFail();
			}
			requests--;
		}
		logger.info("stopping device 1 demo");
	}

	/**
	 * 
	 * - el dispositivo 2, que envía [100-200] actualizaciones de estado a
	 * elasticsearch. El 2% de los estados de dispositivos superarán el umbral de
	 * temperatua, lo que disparará el mecanismo de notificación a los
	 * administradores.
	 * 
	 */
	@Scheduled(fixedDelay = 15000)
	public void device2demo() {

		logger.info("starting device 2 demo");
		int requests = (int) (Math.random() * ((200 - 100) + 1)) + 100;

		while (requests > 0) {

			if (Math.random() > 0.02d) {
				// temperature between 30 and 59
				int temperature = (int) (Math.random() * ((59 - 30) + 1)) + 30;
				DeviceStatus deviceStatus = new DeviceStatus();
				deviceStatus.setDevice(devices[new Random().nextInt(devices.length)]);
				deviceStatus.setTemperature(temperature);
				clientService.sendDeviceStatus(deviceStatus);
			} else {
				// temperature between 60 and 72
				int temperature = (int) (Math.random() * ((72 - 60) + 1)) + 60;
				DeviceStatus deviceStatus = new DeviceStatus();
				deviceStatus.setDevice(devices[new Random().nextInt(devices.length)]);
				deviceStatus.setTemperature(temperature);
				clientService.sendDeviceStatus(deviceStatus);
			}
			requests--;
		}

		logger.info("stopping device 2 demo");
	}

	/**
	 * 
	 * el dispositivo mesh envía [50-100] actualizaciones de estado a través del web
	 * service restful de la aplicaicón cliente de los dispositivos.
	 * 
	 */
	@Scheduled(fixedDelay = 15000)
	public void deviceMeshdemo() {

		logger.info("starting device mesh demo");
		String[] devices = new String[] { "Device 1", "Device 2", "Device 3", "Device 4", "Device 5" };
		int requests = (int) (Math.random() * ((100 - 50) + 1)) + 50;

		while (requests > 0) {

			int temperature = (int) (Math.random() * ((59 - 30) + 1)) + 30;
			DeviceStatus deviceStatus = new DeviceStatus();
			deviceStatus.setDevice(devices[5]);
			deviceStatus.setTemperature(temperature);
			clientService.sendDeviceStatusMesh("localhost", deviceStatus);
			requests--;
		}

		logger.info("stopping device mesh demo");
	}

}
