package com.example.springsecurity.config;

import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;

/**
 * This class is done so that Spring can do the following
 *  -Detect the instance of this class during application startup.
 *  -Register the DelegatingFilterProxy to use the springSecurityFilterChain
 *  before any other registered filter.
 *  -Register a ContextLoaderListener.
 */
public class SpringSecurityInitializer extends AbstractSecurityWebApplicationInitializer {
}
