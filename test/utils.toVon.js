var chai = require("chai");
var utils = require("../packages/web3-utils/src");

var assert = chai.assert;

describe("lib/utils/utils", function() {
    describe("toVon", function() {
        it("should return the correct value", function() {
            assert.equal(utils.toVon("1", "von"), "1");
            assert.equal(utils.toVon("1", "kvon"), "1000");
            assert.equal(utils.toVon("1", "Kvon"), "1000");
            assert.equal(utils.toVon("1", "babbage"), "1000");
            assert.equal(utils.toVon("1", "mvon"), "1000000");
            assert.equal(utils.toVon("1", "Mvon"), "1000000");
            assert.equal(utils.toVon("1", "lovelace"), "1000000");
            assert.equal(utils.toVon("1", "gvon"), "1000000000");
            assert.equal(utils.toVon("1", "Gvon"), "1000000000");
            assert.equal(utils.toVon("1", "shannon"), "1000000000");
            assert.equal(utils.toVon("1", "szabo"), "1000000000000");
            assert.equal(utils.toVon("1", "finney"), "1000000000000000");
            assert.equal(utils.toVon("1", "lat"), "1000000000000000000");
            assert.equal(utils.toVon("1", "klat"), "1000000000000000000000");
            assert.equal(utils.toVon("1", "grand"), "1000000000000000000000");
            assert.equal(utils.toVon("1", "mlat"), "1000000000000000000000000");
            assert.equal(
                utils.toVon("1", "glat"),
                "1000000000000000000000000000"
            );
            assert.equal(
                utils.toVon("1", "tlat"),
                "1000000000000000000000000000000"
            );

            assert.equal(
                utils.toVon("1", "kvon"),
                utils.toVon("1", "femtolat")
            );
            assert.equal(
                utils.toVon("1", "szabo"),
                utils.toVon("1", "microlat")
            );
            assert.equal(
                utils.toVon("1", "finney"),
                utils.toVon("1", "millilat")
            );
            assert.equal(
                utils.toVon("1", "milli"),
                utils.toVon("1", "millilat")
            );
            assert.equal(
                utils.toVon("1", "milli"),
                utils.toVon("1000", "micro")
            );

            assert.throws(function() {
                utils.toVon(1, "von1");
            }, Error);
        });
    });
});
