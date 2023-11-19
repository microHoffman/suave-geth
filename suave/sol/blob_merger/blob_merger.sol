// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.8;

import "../libraries/Suave.sol";

contract BlobMerger {

	event NewBlobSubmited(
		Suave.BidId bidId,
		uint64 decryptionCondition,
		address[] allowedPeekers
	);

	function submitBlobData(uint64 decryptionCondition, address[] memory bidAllowedPeekers, address[] memory bidAllowedStores) external payable {
		require(Suave.isConfidential());

		// TODO shall we rather compute the address + length offset here while storing the data?
		//  then inside the getMergedBlobData we could just work with the blobs including the address + length offset
		bytes memory blobData = Suave.confidentialInputs();
		Suave.Bid memory bid = Suave.newBid(decryptionCondition, bidAllowedPeekers, bidAllowedStores, "blobMerger:v1");
		Suave.confidentialStore(bid.id, "blobMerger:v1", blobData);
		emit NewBlobSubmited(bid.id, bid.decryptionCondition, bid.allowedPeekers);
	}

    function getMergedBlobData(address[] memory toAddresses, Suave.BidId[] memory bidIds) external view returns (bytes[] memory) {
		bytes[] memory blobsData = new bytes[](bidIds.length);
        for (uint i = 0; i < bidIds.length; i++) {
            blobsData[i] = Suave.confidentialRetrieve(bidIds[i], "blobMerger:v1");
        }
		return Suave.mergeBlobData(toAddresses, blobsData);
    }
}