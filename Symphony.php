<?php
/**
 * Symphony Web Services (symws) ILS Driver
 *
 * PHP version 5
 *
 * Copyright (C) Villanova University 2007.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @category VuFind
 * @package  ILS_Drivers
 * @author   Steven Hild <sjhild@wm.edu>
 * @author   Michael Gillen <mlgillen@sfasu.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     http://vufind.org/wiki/building_an_ils_driver Wiki
 */
require_once 'Interface.php';

/**
 * Symphony Web Services (symws) ILS Driver
 *
 * @category VuFind
 * @package  ILS_Drivers
 * @author   Steven Hild <sjhild@wm.edu>
 * @author   Michael Gillen <mlgillen@sfasu.edu>
 * @license  http://opensource.org/licenses/gpl-2.0.php GNU General Public License
 * @link     http://vufind.org/wiki/building_an_ils_driver Wiki
 */

class Symphony implements DriverInterface
{
    protected $config;
  
    /**
     * Constructor
     *
     * @param string $configFile The location of an alternative config file
     *
     * @access public
     */
    public function __construct($configFile = false)
    {
        if ($configFile) {
            // Load Configuration passed in
            $this->config = parse_ini_file('conf/'.$configFile, true);
        } else {
            // Default Configuration
            $this->config = parse_ini_file('conf/Symphony.ini', true);
        }

        // Merge in defaults.
        $this->config += array(
            'WebServices' => array(),
            'LibraryFilter' => array(),
            '999Holdings' => array(),
        );

        $this->config['WebServices'] += array(
            'clientID' => 'VuFind',
            'baseURL' => 'http://localhost:8080/symws',
            'soapOptions' => array(),
        );

        $this->config['LibraryFilter'] += array(
            'include_only' => array(),
            'exclude' => array(),
        );

        $this->config['999Holdings'] += array(
            'entry_number' => 999,
            'mode' => 'off', // also off, failover
        );
    }

    /**
     * Return a SoapClient for the specified SymWS service.
     *
     * This allows SoapClients to be shared and lazily instantiated.
     */
    protected function getSoapClient($service) 
    {
        static $soapClients = array();

        if (!isset($soapClients[$service])) {
            $soapClients[$service] = new SoapClient(
                $this->config['WebServices']['baseURL']."/soap/$service?wsdl",
                $this->config['WebServices']['soapOptions']
            );
        }

        return $soapClients[$service];
    }

    /**
     * Return a SoapHeader for the specified login and password.
     */
    protected function getSoapHeader($login = null, $password = null, 
        $reset = false) 
    {
        $data = array('clientID' => $this->config['WebServices']['clientID']);
        if (!is_null($login)) {
            $data['sessionToken'] = 
                $this->getSessionToken($login, $password, $reset);
        }
        return new SoapHeader(
            'http://www.sirsidynix.com/xmlns/common/header',
            'SdHeader',
            $data
        );
    }

    /**
     * @param boolean $reset if true, replace the currently cached token
     */
    protected function getSessionToken($login, $password, $reset = false) 
    {
        static $sessionTokens = array();

        $key = hash('sha256', "$login:$password");
        
        if (!isset($sessionTokens[$key]) || $reset) {
            if (!$reset && $token = $_SESSION['symws']['session'][$key]) {
                $sessionTokens[$key] = $token;
            } else {
                $params = array('login' => $login);

                if (isset($password)) { 
                    $params['password'] = $password;
                }

                $response = $this->makeRequest('security', 'loginUser', $params);

                $sessionTokens[$key] = $response->sessionToken;

                $_SESSION['symws']['session'] = $sessionTokens;
            }
        }

        return $sessionTokens[$key];
    }

    /**
     * Make a request to Symphony Web Services using the SOAP protocol.
     *
     * @param string $service    the SymWS service name
     * @param string $operation  the SymWS operation name
     * @param array  $parameters the request parameters for the operation
     * @param array  $options    An associative array of additional options,
     *                           with the following elements:
     *                           - 'login': (optional) login to use for
     *                                      (re)establishing a SymWS session
     *                           - 'password': (optional) password to use for
     *                                         (re)establishing a SymWS session
     *                           - 'header': SoapHeader to use, skipping
     *                                       automatic session management
     *
     * @return mixed the result of the SOAP call
     */
    protected function makeRequest($service, $operation, $parameters = array(), 
        $options = array())
    {
        /* If a header was supplied, just use it, skipping everything else. */
        if (isset($options['header'])) {
            return $this->getSoapClient($service)->soapCall($operation,
                $parameters,
                null,
                array($options['header']));
        }

        /* Determine what credentials to use for the SymWS session, if any.
         *
         * If a login and password are specified in $options, use them.
         * If not, for any operation not exempted from SymWS'
         * "Always Require Authentication" option, use the login and password
         * specified in the configuration. Otherwise, proceed anonymously.
         */
        if (isset($options['login'])) {
            $login    = $options['login'];
            $password = isset($options['password'])
                ? $options['password']
                : null;
        } elseif (isset($options['WebServices']['login'])
            && !in_array($operation,
                array('isRestrictedAccess', 'license', 'loginUser', 'version'))
        ) {
            $login    = $this->config['WebServices']['login'];
            $password = isset($this->config['WebServices']['password'])
                ? $this->config['WebServices']['password']
                : null;
        } else {
            $login    = null;
            $password = null;
        }

        /* Attempt the request.
         *
         * If it turns out the SoapHeader's session has expired,
         * get a new one and try again.
         */
        $soapClient = $this->getSoapClient($service);

        try {
            $header = $this->getSoapHeader($login, $password);
            $soapClient->__setSoapHeaders($header);
            return $soapClient->$operation($parameters);
        } catch (SoapFault $e) {
            if ($e->faultcode == 'ns0:com.sirsidynix.symws.service.'
                .'exceptions.SecurityServiceException.sessionTimedOut') {
                $header = $this->getSoapHeader($login, $password, true);
                $soapClient->__setSoapHeaders($header);
                return $soapClient->$operation($parameters);
            } elseif ($operation == 'logoutUser') {
                return null;
            } else {
                throw $e;
            }
        }
    }

    protected function getStatuses_999Holdings($ids) 
    {
        $items = array();
        foreach (VF_Search_Solr_Results::getRecords($ids) as $record) {
            $results = $record->getFormattedMarcDetails(
                $this->config['999Holdings']['entry_number'],
                array(
                    'call number'            => 'marc|a',
                    'copy number'            => 'marc|c',
                    'barcode number'         => 'marc|i',
                    'library'                => 'marc|m',
                    'current location'       => 'marc|k',
                    'home location'          => 'marc|l',
                    'circulate flag'         => 'marc|r',
                ));
            foreach ($results as $result) {
                $library  = $this->translatePolicyID('LIBR', 
                    $result['library']);
                $curr_loc = $this->translatePolicyID('LOCN', 
                    $result['current location']);
                $home_loc = $this->translatePolicyID('LOCN', 
                    $result['home location']);

                $available  =
                    (empty($curr_loc) || $curr_loc == $home_loc)
                    || $result['circulate flag'] == 'Y';
                $callnumber = $result['call number'];
                $location   = $library
                    . ' - '
                    . ($available && !empty($curr_lock)
                        ? $curr_loc : $home_loc);

                $items[] = array(
                    'id' => $result['id'],
                    'availability' => $available,
                    'status' => $curr_loc,
                    'location' => $location,
                    'callnumber' => $callnumber,
                    'barcode' => $result['barcode number'],
                    'number' => $result['copy number'],
                    'reserve' => null,
                );
            }
        }
        return $items;
    }

    protected function lookupTitleInfo($ids) 
    {
        $ids = is_array($ids) ? $ids : array($ids);

        $params = array(
            'titleID' => $ids,
            'includeAvailabilityInfo' => 'true',
            'includeItemInfo' => 'true',
            'includeBoundTogether' => 'true',
        );

        // If only one library is being exclusively included,
        // filtering can be done within Web Services.
        if (count($this->config['LibraryFilter']['include_only']) == 1) {
            $params['libraryFilter'] = 
                $this->config['LibraryFilter']['include_only'][0];
        }

        return $this->makeRequest('standard', 'lookupTitleInfo', $params);
    }

    protected function parseCallInfo($callInfos, $titleID, $is_holdable = false, 
        $bound_in = null)
    {
        $items = array();

        $callInfos = is_array($callInfos) ? $callInfos : array($callInfos);

        foreach ($callInfos as $callInfo) {
            $libraryID = $callInfo->libraryID;

            if ((!empty($this->config['LibraryFilter']['include_only']) &&
                !in_array($libraryID, 
                    $this->config['LibraryFilter']['include_only']))
                || in_array($libraryID, 
                    $this->config['LibraryFilter']['exclude'])) {
                continue;
            }

            $copyNumber = 0; // ItemInfo does not include copy numbers,
                             // so we generate them under the assumption
                             // that items are being listed in order.

            if (!isset($callInfo->ItemInfo)) {
                continue; // no items!
            }

            $itemInfos = is_array($callInfo->ItemInfo)
                ? $callInfo->ItemInfo
                : array($callInfo->ItemInfo);
            foreach ($itemInfos as $itemInfo) {
                $in_transit        = isset($itemInfo->transitReason);
                $currentLocationID = $itemInfo->currentLocationID;
                $homeLocationID    = $itemInfo->homeLocationID;

                /* I would like to be able to write
                 *      $available = $itemInfo->numberOfCharges == 0;
                 * but SymWS does not appear to provide that information.
                 *
                 * SymWS *will* tell me if an item is "chargeable",
                 * but this is inadequate because reference and internet
                 * materials may be available, but not chargeable.
                 *
                 * I can't rely on the presence of dueDate, because
                 * although "dueDate is only returned if the item is currently
                 * checked out", the converse is not true: due dates of NEVER
                 * are simply omitted.
                 *
                 * TitleAvailabilityInfo would be more helpful per item;
                 * as it is, it tells me only number available and library.
                 *
                 * Hence the following criterion: an available item must not
                 * be in-transit, and if it, like exhibits and reserves,
                 * is not in its home location, it must be chargeable.
                 */
                $available = !$in_transit &&
                    ($itemInfo->currentLocationID == $itemInfo->homeLocationID
                    || $itemInfo->chargeable);

                /* Statuses like "Checked out" and "Missing" are represented
                 * by an item's current location. */
                $status = $in_transit
                    ? 'In transit'
                    : $this->translatePolicyID('LOCN', $currentLocationID);

                /* If an item is available, its current location should be
                 * reported as its location. */
                $location = $available
                    ? $this->translatePolicyID('LOCN', $currentLocationID)
                    : $this->translatePolicyID('LOCN', $homeLocationID);

                /* Locations may be shared among libraries, so unless holdings
                 * are being filtered to just one library, it is insufficient
                 * to provide just the location description as the "location".
                 */
                if (count($this->config['LibraryFilter']['include_only'])!=1) {
                    $location = $this->translatePolicyID('LIBR', $libraryID)
                        . ' - ' . $location;
                }

                $library = $this->translatePolicyID('LIBR', $libraryID);

                $material = $this->translatePolicyID('ITYP', $itemInfo->itemTypeID);

                $duedate = isset($itemInfo->dueDate) ? 
                        date('F j, Y', strtotime($itemInfo->dueDate)) : null;
                $duedate = isset($itemInfo->recallDueDate) ? 
                        date('F j, Y', strtotime($itemInfo->recallDueDate)) : 
                        $duedate;

                $requests_placed = isset($itemInfo->numberOfHolds) ? 
                            $itemInfo->numberOfHolds : 0;

                // Handle item notes
                $notes = array();
                
                if (isset($itemInfo->publicNote)) {
                    $notes[] = $itemInfo->publicNote;
                }

                if (isset($itemInfo->staffNote) &&
                    $this->config['Behaviors']['showStaffNotes']) {
                    $notes[] = $itemInfo->staffNote;
                }

                $transitSourceLibrary = 
                    isset($itemInfo->transitSourceLibraryID) ? 
                    $this->translatePolicyID('LIBR',
                        $itemInfo->transitSourceLibraryID) : null;

                $transitDestinationLibrary = 
                    isset($itemInfo->transitDestinationLibraryID) ?
                    $this->translatePolicyID('LIBR', 
                        $itemInfo->transitDestinationLibraryID) : null;

                $transitReason = isset($itemInfo->transitReason) ? 
                    $itemInfo->transitReason : null;

                $transitDate = isset($itemInfo->transitDate) ?
                     date('F j, Y', strtotime($itemInfo->transitDate)) : null;

                $items[] = array(
                    'id' => $titleID,
                    'availability' => $available,
                    'status' => $status,
                    'location' => $location,
                    'reserve' => isset($itemInfo->reserveCollectionID)
                        ? 'Y' : 'N',
                    'callnumber' => $callInfo->callNumber,
                    'duedate' => $duedate,
                    'returnDate' => false, // Not returned by symws
                    'number' => ++$copyNumber,
                    'requests_placed' => $requests_placed,
                    'barcode' => $itemInfo->itemID,
                    'notes' => $notes,
                    'summary' => array(),
                    'is_holdable' => $is_holdable,
                    'holdtype' => 'hold',
                    'addLink' => $is_holdable,
                    'item_id' => $itemInfo->itemID,

                    // The fields below are non-standard and 
                    // should be added to your holdings.tpl
                    // RecordDriver template to be utilized.
                    'library' => $library,
                    'material' => $material,
                    'bound_in' => $bound_in,
                    //'bound_in_title' => ,
                    'transit_source_library' => 
                        $transitSourceLibrary,
                    'transit_destination_library' =>
                        $transitDestinationLibrary,
                    'transit_reason' => $transitReason,
                    'transit_date' => $transitDate
                );
            }
        }
        return $items;
    }

    protected function parseBoundwithLinkInfo($boundwithLinkInfos, $ckey)
    {
        $items = array();

        $boundwithLinkInfos = is_array($boundwithLinkInfos)
            ? $boundwithLinkInfos
            : array($boundwithLinkInfos);

        foreach ($boundwithLinkInfos as $boundwithLinkInfo) {
            // Ignore BoundwithLinkInfos which do not refer to parents
            // or which refer to the record we're already looking at.
            if (!$boundwithLinkInfo->linkedAsParent
             || $boundwithLinkInfo->linkedTitle->titleID == $ckey) {
                continue;
            }

            // Fetch the record that contains the parent CallInfo,
            // identify the CallInfo by matching itemIDs,
            // and parse that CallInfo in the items array.
            $parent_ckey   = $boundwithLinkInfo->linkedTitle->titleID;
            $linked_itemID = $boundwithLinkInfo->itemID;
            $resp          = $this->lookupTitleInfo($parent_ckey);
            $is_holdable   = $resp->TitleInfo->TitleAvailabilityInfo->holdable;

            $callInfos = is_array($resp->TitleInfo->CallInfo)
                ? $resp->TitleInfo->CallInfo
                : array($resp->TitleInfo->CallInfo);

            foreach ($callInfos as $callInfo) {
                $itemInfos = is_array($callInfo->ItemInfo)
                    ? $callInfo->ItemInfo
                    : array($callInfo->ItemInfo);
                foreach ($itemInfos as $itemInfo) {
                    if ($itemInfo->itemID == $linked_itemID) {
                        $items += $this->parseCallInfo($callInfo,
                            $ckey,
                            $is_holdable,
                            $parent_ckey);
                    }
                }
            }
        }

        return $items;
    }

    protected function getLiveStatuses($ids) 
    {
        foreach ($ids as $id) { 
            $items[$id] = array();
        }

        /* In Symphony, a title record has at least one "callnum" record,
         * to which are attached zero or more item records. This structure
         * is reflected in the LookupTitleInfoResponse, which contains
         * one or more TitleInfo elements, which contain one or more
         * CallInfo elements, which contain zero or more ItemInfo elements.
         */
        $response   = $this->lookupTitleInfo($ids);
        $titleInfos = is_array($response->TitleInfo)
            ? $response->TitleInfo
            : array($response->TitleInfo);

        foreach ($titleInfos as $titleInfo) {
            $ckey        = $titleInfo->titleID;
            $is_holdable = $titleInfo->TitleAvailabilityInfo->holdable;

            /* In order to have only one item record per item regardless of
             * how many titles are bound within, Symphony handles titles bound
             * with others by linking callnum records in parent-children
             * relationships, where only the parent callnum has item records
             * attached to it. The CallInfo element of a child callnum
             * does not contain any ItemInfo elements, so we must locate the
             * parent CallInfo using BoundwithLinkInfo, in order to parse
             * the ItemInfo.
             */
            if (isset($titleInfo->BoundwithLinkInfo)) {
                $items[$ckey] = 
                    $this->parseBoundwithLinkInfo($titleInfo->BoundwithLinkInfo, 
                        $ckey);
            }

            /* Callnums that are not bound-with, or are bound-with parents,
             * have item records and can be parsed directly. Since bound-with
             * children do not have item records, parsing them should have no
             * effect. */
            if (!isset($titleInfo->CallInfo)) {
                continue; // no call info!
            }

            $items[$ckey] += $this->parseCallInfo($titleInfo->CallInfo, $ckey, 
                $is_holdable);
        }
        return $items;
    }

    
    /**
     * Translate a Symphony policy ID into a policy description
     * (e.g. VIDEO-COLL => Videorecording Collection).
     *
     * In order to minimize roundtrips with the SymWS server,
     * we fetch more than was requested and cache the results.
     * At time of writing, SymWS did not appear to
     * support retrieving policies of multiple types simultaneously,
     * so we currently fetch only all policies of one type at a time.
     *
     * @param string $policyType The policy type, e.g. Location or Library.
     * @param string $policyID   The policy ID, e.g. VIDEO-COLL or SWEM.
     *
     * @return The policy description, if found, or the policy ID, if not.
     *
     * @todo policy description override 
     */
    protected function translatePolicyID($policyType, $policyID)
    {
        $policyType = strtoupper($policyType); 
        $policyID   = strtoupper($policyID);
        $policyList = array();
        $policyList = $this->getPolicyList($policyType);

        return isset($policyList[$policyID]) ? 
            $policyList[$policyID] : $policyID;
    }

    /**
     * Get Status
     *
     * This is responsible for retrieving the status information of a certain
     * record.
     *
     * @param string $id The record id to retrieve the holdings for
     *
     * @return mixed     On success, an associative array with the following keys:
     * id, availability (boolean), status, location, reserve, callnumber; on
     * failure, a PEAR_Error.
     * @access public
     */
    public function getStatus($id)
    {
        $statuses = $this->getStatuses(array($id));
        return isset($statuses[$id]) ? $statuses[$id] : array();
    }

    /**
     * Get Statuses
     *
     * This is responsible for retrieving the status information for a
     * collection of records.
     *
     * @param array $ids The array of record ids to retrieve the status for
     *
     * @return mixed        An array of getStatus() return values on success,
     * a PEAR_Error object otherwise.
     * @access public
     */
    public function getStatuses($ids)
    {
        if ($this->config['999Holdings']['mode'] == 'on') {
            return $this->getStatuses_999Holdings($ids);
        } else {
            return $this->getLiveStatuses($ids);
        }
    }

    /**
     * Get Holding
     *
     * This is responsible for retrieving the holding information of a certain
     * record.
     *
     * @param string $id     The record id to retrieve the holdings for
     * @param array  $patron Patron data
     *
     * @return mixed     On success, an associative array with the following keys:
     * id, availability (boolean), status, location, reserve, callnumber, duedate,
     * number, barcode; on failure, a PEAR_Error.
     * @access public
     */
    public function getHolding($id, $patron = false)
    {
        return $this->getStatus($id);
    }

    /**
     * Get Purchase History
     *
     * This is responsible for retrieving the acquisitions history data for the
     * specific record (usually recently received issues of a serial).
     *
     * @param string $id The record id to retrieve the info for
     *
     * @return mixed An array with the acquisitions data on success, PEAR_Error
     * on failure
     * @access public
     */
    public function getPurchaseHistory($id)
    {
        return array();
    }

    /**
     * Login Is Hidden
     *
     * This method can be used to hide VuFind's login options
     *
     * @return boolean true if login options should be hidden, false if not.
     * @access public
     */
    public function loginIsHidden()
    {
        if (isset($this->config['Behaviors']['showAccountLogin']) 
            && ($this->config['Behaviors']['showAccountLogin'] == false)) {
            return true;
        } else {
            return false;
        }
    }

     /**
     * Patron Login
     *
     * This is responsible for authenticating a patron against the catalog.
     *
     * @param string $username The patron username
     * @param string $password The patron password
     *
     * @return mixed           Associative array of patron info on successful login,
     * null on unsuccessful login, PEAR_Error on error.
     * @access public
     */
    public function patronLogin($username, $password) 
    {
        $usernameField = 
                $this->config['Behaviors']['usernameField'];

        $patron = array(
            'cat_username' => $username,
            'cat_password' => $password,
        );

        $resp = $this->makeRequest('patron',
            'lookupMyAccountInfo',
            array(
                'includePatronInfo' => 'true',
                'includePatronAddressInfo' => 'true'
            ),
            array(
                'login' => $username,
                'password' => $password,
            ));

        $patron['id'] = $resp->patronInfo->$usernameField;

        if (preg_match('/([^,]*),\s([^\s]*)/', $resp->patronInfo->displayName, 
            $matches)) {
            $patron['firstname'] = $matches[2];
            $patron['lastname']  = $matches[1];
        }

        // @TODO: email, major, college

        return $patron;
    }

    /**
     * Get Patron Profile
     *
     * This is responsible for retrieving the profile for a specific patron.
     *
     * @param array $patron The patron array
     *
     * @return mixed        Array of the patron's profile data on success,
     * PEAR_Error otherwise.
     * @access public
     */
    public function getMyProfile($patron)
    {
        try {
            $userProfileGroupField = 
                $this->config['Behaviors']['userProfileGroupField'];

            $options = array(
                'includePatronInfo' => 'true',
                'includePatronAddressInfo' => 'true',
                'includePatronStatusInfo' => 'true',
                'includeUserGroupInfo'     => 'true'
            );

            $result = $this->makeRequest('patron',
                'lookupMyAccountInfo',
                $options,
                array(
                    'login' => $patron['cat_username'],
                    'password' => $patron['cat_password']
                ));

            $primaryAddress = $result->patronAddressInfo->primaryAddress;

            $primaryAddressInfo = "Address" . $primaryAddress . "Info";

            $addressInfo = $result->patronAddressInfo->$primaryAddressInfo;
            $address1    = $addressInfo[0]->addressValue;
            $address2    = $addressInfo[1]->addressValue;
            $zip         = $addressInfo[2]->addressValue;
            $phone       = $addressInfo[3]->addressValue;

            if (strcmp($userProfileGroupField, 'GROUP_ID') == 0) {
                $group = $result->patronInfo->groupID;
            } elseif (strcmp($userProfileGroupField, 'USER_PROFILE_ID') == 0) {
                $group = $this->makeRequest('security',
                    'lookupSessionInfo',
                    $options,
                    array(
                        'login' => $patron['cat_username'],
                        'password' => $patron['cat_password']
                    ))->userProfileID;
            } elseif (strcmp($userProfileGroupField, 'PATRON_LIBRARY_ID') == 0) {
                $group = $result->patronInfo->patronLibraryID;
            } elseif (strcmp($userProfileGroupField, 'DEPARTMENT') == 0) {
                $group = $result->patronInfo->department;
            } else {
                $group = null;
            }

            list($lastname,$firstname) = explode(', ', 
                                            $result->patronInfo->displayName);

            $profile = array(
                'lastname' => $lastname,
                'firstname' => $firstname,
                'address1' => $address1,
                'address2' => $address2,
                'zip' => $zip,
                'phone' => $phone,
                'group' => $group
            );

            return $profile;
        } catch (Exception $e) {
            return new PEAR_Error($e->getMessage());
        }
    }

    /**
     * Get Patron Transactions
     *
     * This is responsible for retrieving all transactions (i.e. checked out items)
     * by a specific patron.
     *
     * @param array $patron The patron array from patronLogin
     *
     * @return mixed        Array of the patron's transactions on success,
     * PEAR_Error otherwise.
     * @access public
     */
    public function getMyTransactions($patron)
    {
        try {
            $transList = array();
            $options   = array('includePatronCheckoutInfo' => 'ALL');

            $result = $this->makeRequest('patron',
                'lookupMyAccountInfo',
                $options,
                array(
                    'login' => $patron['cat_username'],
                    'password' => $patron['cat_password']
                ));

            if (isset($result->patronCheckoutInfo)) {
                $transactions = $result->patronCheckoutInfo;
                $transactions = !is_array($transactions) ? array($transactions) : 
                    $transactions;

                foreach ($transactions as $transaction) {
                    if ($transaction->unseenRenewalsRemaining > 0) {
                        $renewable = true;
                    } else {
                        $renewable = false;
                    }

                    $transList[] = array(
                        'duedate' => date('F j, Y',
                            strtotime($transaction->dueDate)),
                        'id' => $transaction->titleKey,
                        'barcode' => $transaction->itemID,
                        'renew' => $transaction->renewals,
                        'request' => $transaction->recallNoticesSent,
                        //'volume' => null,
                        //'publication_year' => null,
                        'renewable' => $renewable,
                        //'message' => null,
                        'title' => $transaction->title,
                        'item_id' => $transaction->itemID
                    );
                }
            }
            return $transList;
        } catch (Exception $e) {
            return new PEAR_Error($e->getMessage());
        }
    }

    /**
     * Get Patron Holds
     *
     * This is responsible for retrieving all holds by a specific patron.
     *
     * @param array $patron The patron array from patronLogin
     *
     * @return mixed        Array of the patron's holds on success, PEAR_Error
     * otherwise.
     * @access public
     */
    public function getMyHolds($patron)
    {
        try {
            $holdList = array();
            $options  = array('includePatronHoldInfo' => 'ACTIVE');

            $result = $this->makeRequest('patron',
                'lookupMyAccountInfo',
                $options,
                array(
                    'login' => $patron['cat_username'],
                    'password' => $patron['cat_password']
                ));
            
            if (!property_exists($result, 'patronHoldInfo')) {
                return null;
            }
            
            $holds = $result->patronHoldInfo;
            $holds = !is_array($holds) ? array($holds) : $holds;

            foreach ($holds as $hold) {
                $holdList[] = array(
                    'id' => $hold->titleKey,
                    //'type' => ,
                    'location' => $hold->pickupLibraryID,
                    'reqnum' => $hold->holdKey,
                    'expire' => date('F j, Y',
                        strtotime($hold->expiresDate)),
                    'create' => date('F j, Y',
                        strtotime($hold->placedDate)),
                    'position' => $hold->queuePosition,
                    'available' => $hold->available,
                    'item_id' => $hold->itemID,
                    //'volume' => null,
                    //'publication_year' => null,
                    'title' => $hold->title
                );
            }
            return $holdList;
        } catch(SoapFault $e) {
            return null;
        } catch(Exception $e) {
            return new PEAR_Error($e->getMessage());
        }
    }

    /**
     * Get Patron Fines
     *
     * This is responsible for retrieving all fines by a specific patron.
     *
     * @param array $patron The patron array from patronLogin
     *
     * @return mixed        Array of the patron's fines on success, PEAR_Error
     * otherwise.
     * @access public
     */
    public function getMyFines($patron)
    {
        try {
            $fineList = array();
            $feeType  = $this->config['Behaviors']['showFeeType'];
            $options  = array('includeFeeInfo' => $feeType);

            $result = $this->makeRequest('patron',
                'lookupMyAccountInfo',
                $options,
                array(
                    'login' => $patron['cat_username'],
                    'password' => $patron['cat_password']
                ));

            if (isset($result->feeInfo)) {
                $fees = $result->feeInfo;
                $fees = !is_array($fees) ? array($fees) : $fees;

                foreach ($fees as $fee) {
                    $fineList[] = array(
                        'amount' => $fee->amount->_ * 100,
                        'checkout' =>
                            isset($fee->feeItemInfo->checkoutDate) ? 
                            $fee->feeItemInfo->checkoutDate : null,
                        'fine' => $fee->billReasonDescription,
                        'balance' => $fee->amountOutstanding->_ * 100,
                        'createdate' => 
                            isset($fee->feeItemInfo->dateBilled) ? 
                            $fee->feeItemInfo->dateBilled : null,
                        'duedate' =>
                            isset($fee->feeItemInfo->dueDate) ?
                            $fee->feeItemInfo->dueDate : null,
                        'id' => isset($fee->feeItemInfo->titleKey) ?
                            $fee->feeItemInfo->titleKey : null
                    );
                }
            }
           
            return $fineList;
        } catch (SoapFault $e) {
            return new PEAR_Error($e->getMessage());
        } catch(Exception $e) {
            return new PEAR_Error($e->getMessage());
        }
    }

    /**
     * Get Cancel Hold Form
     *
     * Supplies the form details required to cancel a hold
     *
     * @param array $holdDetails An array of item data
     *
     * @return string  Data for use in a form field
     * @access public
     */
    public function getCancelHoldDetails($holdDetails)
    {
        return $holdDetails['reqnum'];
    }

     /**
     * Cancel Holds
     *
     * Attempts to Cancel a hold on a particular item
     *
     * @param array $cancelDetails An array of item and patron data
     *
     * @return mixed  An array of data on each request including
     * whether or not it was successful and a system message (if available)
     * or boolean false on failure
     * @access public
     */
    public function cancelHolds($cancelDetails)
    {
        $count  = 0;
        $items  = array();
        $patron = $cancelDetails['patron'];
        
        foreach ($cancelDetails['details'] as $holdKey) {
            try {
                $options = array('holdKey' => $holdKey);

                $hold = $this->makeRequest('patron',
                    'cancelMyHold',
                    $options,
                    array(
                        'login' => $patron['cat_username'],
                        'password' => $patron['cat_password']
                    ));
                
                $count++;
                $items[$holdKey] = array(
                    'success' => true, 
                    'status' => 'hold_cancel_success'
                );
            } catch (Exception $e) {
                $items[$holdKey] = array(
                    'success' => false, 
                    'status' => 'hold_cancel_fail',
                    'sysMessage' => $e->getMessage()
                );
            }
        }
        $result = array('count' => $count, 'items' => $items);
        return $result;
    }

     /**
     * Public Function which retrieves renew, hold and cancel settings from the
     * driver ini file.
     *
     * @param string $function The name of the feature to be checked
     *
     * @return array An array with key-value pairs.
     * @access public
     */
    public function getConfig($function)
    {
        if (isset($this->config[$function]) ) {
            $functionConfig = $this->config[$function];
        } else {
            $functionConfig = false;
        }
        return $functionConfig;
    }

    /**
     * Get Renew Details
     *
     * In order to renew an item, Symphony requires the patron details and an item
     * id. This function returns the item id as a string which is then used
     * as submitted form data in checkedOut.php. This value is then extracted by
     * the RenewMyItems function.
     *
     * @param array $checkOutDetails An array of item data
     *
     * @return string Data for use in a form field
     */
    public function getRenewDetails($checkOutDetails)
    {
        $renewDetails = $checkOutDetails['barcode'];
        return $renewDetails;
    }

    /**
     * Renew My Items
     *
     * Function for attempting to renew a patron's items.  The data in
     * $renewDetails['details'] is determined by getRenewDetails().
     *
     * @param array $renewDetails An array of data required for renewing items
     * including the Patron ID and an array of renewal IDS
     *
     * @return array              An array of renewal information keyed by item ID
     */
    public function renewMyItems($renewDetails)
    {
        $blocks  = array();
        $details = array();
        $patron  = $renewDetails['patron'];

        foreach ($renewDetails['details'] as $barcode) {
            try {
                $options = array('itemID' => $barcode);

                $renewal = $this->makeRequest('patron',
                    'renewMyCheckout',
                    $options,
                    array(
                        'login' => $patron['cat_username'],
                        'password' => $patron['cat_password'],
                    ));

                $details[$barcode] = array(
                    'success' => true,
                    'new_date' => date('j-M-y',
                        strtotime($renewal->dueDate)),
                    'new_time' =>date('g:i a',
                        strtotime($renewal->dueDate)),
                    'item_id' => $renewal->itemID,
                    'sysMessage' => $renewal->message
                );
            } catch (Exception $e) {
                $details[$barcode] = array(
                    'success' => false,
                    'new_date' => false,
                    'new_time' => false,
                    'sysMessage' => 
                        'We could not renew this item: ' . $e->getMessage()
                );
            }
        }

        $result = array('details' => $details);
        return $result;
    }

    /**
     * Place Hold
     *
     * Attempts to place a hold or recall on a particular item
     *
     * @param array $holdDetails An array of item and patron data
     *
     * @return array  An array of data on the request including
     * whether or not it was successful and a system message (if available)
     * @access public
     */
    public function placeHold($holdDetails)
    {
        try {
            $options = array();
            $patron  = $holdDetails['patron'];

            if ($holdDetails['item_id'] != null) {
                $options['itemID'] = $holdDetails['item_id'];
            }

            if ($holdDetails['id'] != null) {
                $options['titleID'] = $holdDetails['id'];
            }

            if ($holdDetails['pickUpLocation'] != null) {
                $options['pickupLibraryID'] = $holdDetails['pickUpLocation'];
            }

            if ($holdDetails['requiredBy'] != null) {
                $options['expiresDate'] = $holdDetails['requiredBy'];
            }

            if ($holdDetails['comment'] != null) {
                $options['comment'] = $holdDetails['comment'];
            }

            $hold = $this->makeRequest('patron',
                'createMyHold',
                $options,
                array(
                    'login' => $patron['cat_username'],
                    'password' => $patron['cat_password']
                ));

            $result = array(
                'success' => true,
                'sysMessage' => 'Your hold has been placed.'
            );
            return $result;
        } catch (SoapFault $e) {
            $result = array(
                'success' => false,
                'sysMessage' =>
                    'We could not place the hold: ' . $e->getMessage()
            );
            return $result;
        }
    }

    /**
     * Protected support method for getting a list of policies.
     *
     * @return array An associative array of policy codes and descriptions.
     * @access protected
     */
    protected function getPolicyList($policyType)
    {
        if (isset($_SESSION['symws']['policies'][$policyType])) {
            return $_SESSION['symws']['policies'][$policyType];
        }

        try {
            $policyList = array();

            $options = array('policyType' => $policyType);

            $policies = $this->makeRequest('admin', 'lookupPolicyList', $options);

            foreach ($policies->policyInfo as $policyInfo) {
                $policyList[$policyInfo->policyID] = 
                    $policyInfo->policyDescription;
            }

            $_SESSION['symws']['policies'][$policyType] = $policyList;
            return $policyList;
        } catch (Exception $e) {
            return array();
        }
    }

    /**
     * Get Pick Up Locations
     *
     * This is responsible get a list of valid library locations for holds / recall
     * retrieval
     *
     * @param array $patron      Patron information returned by the patronLogin
     * method.
     * @param array $holdDetails Optional array, only passed in when getting a list
     * in the context of placing a hold; contains most of the same values passed to
     * placeHold, minus the patron data.  May be used to limit the pickup options
     * or may be ignored.  The driver must not add new options to the return array
     * based on this data or other areas of VuFind may behave incorrectly.
     *
     * @return array        An array of associative arrays with locationID and
     * locationDisplay keys
     * @access public
     */
    public function getPickUpLocations($patron = false, $holdDetails = null)
    {
        $libraries = array();

        foreach ($this->getPolicyList('LIBR') as $key=>$library) {
            $libraries[] = array(
                'locationID' => $key,
                'locationDisplay' => $library
            );
        }
 
        return $libraries;
    }
}
?>
