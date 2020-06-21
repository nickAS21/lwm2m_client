package org.thingsboard.lwm2m.client;

import lombok.extern.slf4j.Slf4j;
import org.eclipse.leshan.client.californium.LeshanClient;
import org.eclipse.leshan.client.resource.LwM2mObjectEnabler;
import org.eclipse.leshan.client.resource.listener.ObjectsListenerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@Slf4j
@Service("LwM2MClientInitializer")
public class LwM2MClientInitializer {

    @Autowired
    private LeshanClient client;

    @PostConstruct
    public void init() {

        log.info("init client");
        this.client.getObjectTree().addListener(new ObjectsListenerAdapter() {
            @Override
            public void objectRemoved(LwM2mObjectEnabler object) {
                log.info("Object [{}] disabled.", object.getId());
            }

            @Override
            public void objectAdded(LwM2mObjectEnabler object) {
                log.info("Object [{}] enabled.", object.getId());
            }
        });
        /** Start the client */
        this.client.start();

        /** De-register on shutdown and stop client. */
        Runtime.getRuntime().addShutdownHook(new Thread() {
            @Override
            public void run() {
                client.destroy(true); // send de-registration request before destroy
            }
        });

    }

    @PreDestroy
    public void shutdown()  {
        log.info("Stopping LwM2M thingsboard client!");
        try {
            client.destroy(true);
        } finally {
        }
        log.info("LwM2M thingsboard client stopped!");
    }

}
