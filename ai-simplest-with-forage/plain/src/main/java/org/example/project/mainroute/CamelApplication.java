package org.example.project.mainroute;

import org.apache.camel.main.Main;

public class CamelApplication {

    public static void main(String[] args) throws Exception {
        Main main = new Main(CamelApplication.class);
        main.run(args);
    }

}
