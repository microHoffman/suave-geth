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

		bytes memory blobData = Suave.confidentialInputs();

		Suave.Bid memory bid = Suave.newBid(decryptionCondition, bidAllowedPeekers, bidAllowedStores, "blobMerger:v1");

		Suave.confidentialStore(bid.id, "blobMerger:v1", blobData);
		emit NewBlobSubmited(bid.id, bid.decryptionCondition, bid.allowedPeekers);
	}

    function getMergedBlobData(Suave.BidId[] memory bids) external view returns (bytes[] memory) {
        bytes[] memory blobsData = new bytes[](bids.length);
        for (uint i = 0; i < bids.length; i++) {
            blobsData[i] = Suave.confidentialRetrieve(bids[i], "blobMerger:v1");
        }
        bytes[] memory mergedBlobs = Suave.mergeBlobData(blobsData);
        return mergedBlobs;
    }
}