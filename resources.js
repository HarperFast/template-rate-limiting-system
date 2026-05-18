import { Resource, databases, getContext } from 'harper';
const { subscriber_log } = databases.ratelimit;

/**
 * Rate Limiting System
 * Alias name: VOD Segment Access Control System
 * This module handles subscriber log entries and provides the logic
 * to prevent bot users from accessing resources (VOD segments).
 */

// Define Piracy check limits
// Time interval in seconds ( Default : 10 seconds)
const TIME_INTERVAL = 10;
// Number of requests for unique combination of subscriberID and Contentname ( Default: 50 )
const REQUESTS_COUNT = 50;
// Number of unique client IP for unique combination of subscriberID and ContentName ( Default : 4 )
const CLIENT_IPS = 4;
// Number of unique ContentName for unique combination of subscriberID ( Default : 4 )
const CONTENT_NAMES = 4;
// Number of unique SessionID for unique combination of subscriberID and clientIP ( Default : 1 )
const SESSION_IDS = 1;

export class subscriberlog extends Resource {
    /**
     * Logs a new subscriber event and performs piracy checks
     * POST /subscriberlog
     *
     * @param {Object} data - The subscriber event data
     * @param {string} data.subscriberId - Subscriber ID (required)
     * @param {string} data.clientsessionId - Client Session ID
     * @param {string} data.clientIP - Client IP address
     * @param {string} data.edgeIP - Edge IP address
     * @param {string} data.Contentname - Content Name
     * @param {string} data.useragent - User Agent of the request
     * @param {string} data.Host - Host component of the URL
     * @param {string} data.Path - Request Path component of URL
     * @param {string} data.clientLocation - Client Location
     * @throws {Error} If subscriberId is missing
     * @returns {string} Confirmation message
     */
    async post(data) {

        const context = getContext();

        try {
            if (!data.subscriberId) {
                throw this.createError('Deny. SubscriberId is required.', 400);
            }

            const now = Date.now();
            const startTime = now - (TIME_INTERVAL * 1000); // transform from seconds to milliseconds

            // Building a new object to be stored in the SubscriberLog table.
            const subLog = {
                // The primary key `subscriberId` is stored as an array of subscriberId & time to make time based searches
                // more performant and to allow multiple entries per subscriber.
                subscriberId: [data.subscriberId, now],
                clientsessionId: data.clientsessionId,
                clientIP: data.clientIP,
                edgeIP: data.edgeIP,
                time: now,
                contentname: data.Contentname,
                useragent: data.useragent,
                host: data.Host,
                path: data.Path,
                clientlocation: data.clientLocation,
            }

            // Run database put operation and piracy check concurrently
            const [pirateConditions,] = await Promise.all([
                // Piracy checks not taking in consideration current entry
                this.checkPirateConditions(data.subscriberId, startTime, now-1),
                // Write subscriber log into DB
                subscriber_log.put(subLog)
            ]);

            // Set response headers based on piracy check results
            context.responseHeaders.set('X-subscriber-pirate', pirateConditions.isPirate ? 'True' : 'False');
            if (pirateConditions.isPirate) {
                context.responseHeaders.set('X-subscriber-condition', pirateConditions.conditionHeader);
            }
            context.responseHeaders.set('X-subscriber-blacklist', 'False');

            return "{'OK'}";
        } catch (error) {
            context.responseHeaders.set('X-Data-Update', String(error));
            throw this.createError(error, 504);
        }
    }

    /**
     * Check for piracy conditions based on recent subscriber activity
     * Performs a single database query and processes the data in memory
     *
     * @param {string} subscriberId - Subscriber ID
     * @param {number} startTime - Start time for the check window in milliseconds
     * @param {number} endTime - End time for the check window in milliseconds
     * @returns {Object} Object indicating if the subscriber is a pirate and which condition was met
     */
    async checkPirateConditions(subscriberId, startTime, endTime) {
        // Initialize data structures for condition checking
        const requestsCount = new Map();
        const uniqueClientIPs = new Map();
        const uniqueContentNames = new Set();
        const uniqueSessionIds = new Map();
        const metConditions = new Set();

        // Single database query to fetch all relevant logs
        for await (const log of subscriber_log.search({
            conditions: [
                { attribute: 'subscriberId', comparator: 'between', value: [[subscriberId, startTime], [subscriberId, Number(endTime)]] }
            ]
        })) {
            const contentName = log.contentname;
            const clientIP = log.clientIP;
            const sessionId = log.clientsessionId;

            // Condition 1: Number of requests for unique combination of subscriberID and Contentname (in 10 seconds)
            const requestKey = `${contentName}`;
            requestsCount.set(requestKey, (requestsCount.get(requestKey) || 0) + 1);
            if (requestsCount.get(requestKey) > REQUESTS_COUNT) {
                metConditions.add('high_requests');
            }

            // Condition 2: Number of unique client IP for unique combination of subscriberID and ContentName
            if (!uniqueClientIPs.has(contentName)) {
                uniqueClientIPs.set(contentName, new Set());
            }
            uniqueClientIPs.get(contentName).add(clientIP);
            if (uniqueClientIPs.get(contentName).size > CLIENT_IPS) {
                metConditions.add('high_ip_count');
            }

            // Condition 3: Number of unique ContentName for unique combination of subscriberID
            uniqueContentNames.add(contentName);
            if (uniqueContentNames.size > CONTENT_NAMES) {
                metConditions.add('multiple_content_views');
            }

            // Condition 4: Number of unique SessionID for unique combination of subscriberID and clientIP
            const sessionKey = `${clientIP}`;
            if (!uniqueSessionIds.has(sessionKey)) {
                uniqueSessionIds.set(sessionKey, new Set());
            }
            uniqueSessionIds.get(sessionKey).add(sessionId);
            if (uniqueSessionIds.get(sessionKey).size > SESSION_IDS) {
                metConditions.add('multiple_sessions');
            }

            // Stop processing if all conditions are met
            if (metConditions.size === 4) {
                break;
            }
        }

        // Determine if the subscriber is a pirate and which conditions were met
        const isPirate = metConditions.size > 0;
        const conditionHeader = Array.from(metConditions).join(',');

        // Return piracy condition check result
        return { isPirate: isPirate, conditionHeader: isPirate ? conditionHeader : undefined };
    }

    /**
     * Helper function to create an error with a defined status code
     *
     * @param {string} message - Error message
     * @param {number} statusCode - HTTP status code
     * @returns {Error} Error object with status code
     */
    createError(message, statusCode) {
        const error = new Error(message);
        error.statusCode = statusCode;
        return error;
    }
}