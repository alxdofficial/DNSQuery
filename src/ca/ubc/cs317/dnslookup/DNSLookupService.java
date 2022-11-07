package ca.ubc.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.*;

public class DNSLookupService {

    private static boolean p1Flag = false; // isolating part 1
    private static final int MAX_INDIRECTION_LEVEL = 10;
    private static InetAddress rootServer;
    private static DNSCache cache = DNSCache.getInstance();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length == 2 && args[1].equals("-p1")) {
            p1Flag = true;
        } else if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            DNSQueryHandler.openSocket();
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    boolean verboseTracing = false;
                    if (commandArgs[1].equalsIgnoreCase("on")) {
                        verboseTracing = true;
                        DNSQueryHandler.setVerboseTracing(true);
                    }
                    else if (commandArgs[1].equalsIgnoreCase("off")) {
                        DNSQueryHandler.setVerboseTracing(false);
                    }
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            }
            else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
            }

        } while (true);

        DNSQueryHandler.closeSocket();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {
        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the results for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (p1Flag) { // For isolating part 1 testing only
            retrieveResultsFromServer(node, rootServer);
            return Collections.emptySet();
        } else if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        } else {
            // TODO (PART 1/2): Implement this
            //first check if we already have the answer
            if (cache.getCachedResults(node).size() > 0) {
                return cache.getCachedResults(node);
            }

                retrieveResultsFromServer(node, rootServer);

            //create nodes of each type to help with searching in the cache
            DNSNode ANode = new DNSNode(node.getHostName(), RecordType.A);
            DNSNode AAAANode = new DNSNode(node.getHostName(), RecordType.AAAA);
            DNSNode CnameNode = new DNSNode(node.getHostName(), RecordType.CNAME);
            //first check if we have cnames not resolved
            Set<ResourceRecord> results = new HashSet<>(cache.getCachedResults(CnameNode));
            for (ResourceRecord r : results) {
                // if we got a cname result
                if (r.getType() == RecordType.CNAME &&
                        !(resourceRecordsContainsType(results, RecordType.A) ||
                                resourceRecordsContainsType(results,RecordType.AAAA))) {
                    return getResults(new DNSNode(r.getTextResult(), node.getType()), indirectionLevel + 1);
                }
            }
            //now we for sure have either A/AAAA results or our domain is bad
            Set<ResourceRecord> returnResults = new HashSet<>();
            if (node.getType() == RecordType.A) {returnResults.addAll(cache.getCachedResults(ANode));}
            if (node.getType() == RecordType.AAAA) {returnResults.addAll(cache.getCachedResults(AAAANode));}
            return returnResults;
        }
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        byte[] message = new byte[512]; // query is no longer than 512 bytes

        try {
            DNSServerResponse serverResponse = DNSQueryHandler.buildAndSendQuery(message, server, node);

            Set<ResourceRecord> nameservers = DNSQueryHandler.decodeAndCacheResponse(serverResponse.getTransactionID(),
                    serverResponse.getResponse(),
                    cache);
            if (nameservers == null) nameservers = Collections.emptySet();

            if (p1Flag) return; // For testing part 1 only

            queryNextLevel(node, nameservers);

        } catch (IOException | NullPointerException ignored){}
    }

    /**
     * Query the next level DNS Server, if necessary
     *
     * @param node        Host name and record type of the query.
     * @param records List of name servers returned from the previous level to query the next level.
     */
    private static void queryNextLevel(DNSNode node,Set<ResourceRecord> records) {
        boolean done = false;
        if (resourceRecordSetContains(records, RecordType.A,node) || resourceRecordSetContains(records, RecordType.AAAA,node)
        || resourceRecordSetContains(records, RecordType.CNAME,node)) {
            //if previous level returned a or aaaa or cname records, no need to query anymore.
            done = true; //for debugging
        } else if (resourceRecordsContainsType(records,RecordType.NS)) {
            // if we get name servers, we query the first one, if the first one doesn't respond we query the next one until there is no more.
            //if we exhaust all the NSs, print an error and give up.

            //create a set of just NS records
            Set<ResourceRecord> nsRecords = new HashSet<>();
            for (ResourceRecord r : records) {
                if (r.getType() == RecordType.NS) {nsRecords.add(r);}
            }
            //pick the first server in that set to query next, if this server don't work, change to another one
            ResourceRecord nextServer = nsRecords.iterator().next();
            boolean continueQueryingThisLevel = true;
            int tries = 0;
            //create a set of next servers that will be returned after we query this layer, if it is null, it means are query did not return proper response
            Set<ResourceRecord> nextLevel = null;
            while (nsRecords.iterator().hasNext() && continueQueryingThisLevel && tries < 5) {
                tries++;
                try {
                    //create packet and send
                    byte[] packeBuffer = new byte[256];
                    String nextServerName = nextServer.getTextResult();
                    DNSServerResponse response = DNSQueryHandler.buildAndSendQuery(packeBuffer,
                            InetAddress.getByName(nextServerName),node);
                    //update next servers list
                    nextLevel = DNSQueryHandler.decodeAndCacheResponse(response.getTransactionID(),
                            response.getResponse(), cache);
                    if (nextLevel != null) {
                        //next servers found
                        continueQueryingThisLevel = false;
                        queryNextLevel(node, nextLevel);
                    } else {
                        System.err.println("query failed because a level did not return valid next servers");
                    }
                } catch (IOException e) {
                    System.err.println(e.getMessage());
                    System.err.println("querying next level failed because IO exception");
                }
                nextServer = nsRecords.iterator().next();
            }
        } else {
            System.err.println("query failed because no A/AAAA/CNAME found after querying all layers");
        }
    }
//

    private static boolean resourceRecordSetContains(Set<ResourceRecord> set, RecordType type, DNSNode node) {
        for (ResourceRecord rr : set) {
            if (rr.getType() == type && Objects.equals(rr.getHostName(), node.getHostName())) {
//                System.out.println(rr.getHostName() + " " + rr.getType() + " == " + type);
                return true;
            }
        }
        return false;
    }
    private static boolean resourceRecordsContainsType(Set<ResourceRecord> set, RecordType type) {
        for (ResourceRecord rr : set) {
            if (rr.getType() == type) {
//                System.out.println(rr.getHostName() + " " + rr.getType() + " == " + type);
                return true;
            }
        }
        return false;
    }


    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
