package me.elyor.ssogateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.ApplicationPidFileWriter;

@SpringBootApplication
public class SsoGateway {

	public static void main(String[] args) {
		SpringApplication app = new SpringApplication(SsoGateway.class);
		app.addListeners(new ApplicationPidFileWriter());
		app.run(args);
	}
}
